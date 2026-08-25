from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4
import sqlite3

from typing import Annotated
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
)

from app.idempotency import (
    IdempotencyRecord,
    build_request_fingerprint,
)

from app.approval_models import (
    ApprovalRecord,
    ApprovalRequestPage,
    ApprovalResolutionRequest,
    ApprovalResolutionStatus,
    ApprovalStatus,
)

from app.authorization_models import (
    AuthorizationDecisionPage,
    AuthorizationRequest,
    AuthorizationResponse,
)
from app.evidence_store import EvidenceStore
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    InvalidPolicyContextError,
)
from app.policy_engine import evaluate_policy

from app.security import (
    get_configured_api_key,
    require_api_key,
)

DATABASE_PATH = Path("data/regtrace.db")
evidence_store = EvidenceStore(DATABASE_PATH)

@asynccontextmanager
async def lifespan(_: FastAPI):
    get_configured_api_key()
    evidence_store.initialize()
    yield


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
    lifespan=lifespan,
)


def get_evidence_store() -> EvidenceStore:
    return evidence_store

def _get_idempotent_authorization(
    store: EvidenceStore,
    idempotency_key: str,
    request_fingerprint: str,
) -> AuthorizationResponse | None:
    existing_record = store.get_idempotency_record(
        idempotency_key
    )

    if existing_record is None:
        return None

    if (
        existing_record.request_fingerprint
        != request_fingerprint
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "idempotency_key_conflict",
                "message": (
                    "Idempotency key has already been "
                    "used with a different request."
                ),
            },
        )

    authorization = store.get(
        existing_record.decision_id
    )

    if authorization is None:
        raise RuntimeError(
            "Idempotency record references a missing "
            "authorization decision."
        )

    return authorization


def _resolve_approval_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    status: ApprovalResolutionStatus,
    store: EvidenceStore,
) -> ApprovalRecord:
    try:
        return store.resolve_approval(
            decision_id=decision_id,
            status=status,
            resolved_by=resolution.resolved_by,
            resolved_at=datetime.now(timezone.utc),
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "approval_not_found",
                "message": str(exc),
            },
        ) from exc
    except ApprovalAlreadyResolvedError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval_already_resolved",
                "message": str(exc),
                "current_status": exc.current_status,
            },
        ) from exc


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post(
    "/v1/authorize",
    response_model=AuthorizationResponse,
    dependencies=[Depends(require_api_key)],
)
def authorize(
    request: AuthorizationRequest,
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            min_length=1,
            max_length=255,
        ),
    ] = None,
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationResponse:
    request_fingerprint = None

    if idempotency_key is not None:
        request_fingerprint = build_request_fingerprint(
            request
        )

        existing_authorization = (
            _get_idempotent_authorization(
                store=store,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        )

        if existing_authorization is not None:
            return existing_authorization

    try:
        evaluation = evaluate_policy(
            request.action,
            request.context,
        )
    except InvalidPolicyContextError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_policy_context",
                "message": str(exc),
                "field": exc.field,
                "operator": exc.operator,
            },
        ) from exc

    authorization = AuthorizationResponse(
        decision_id=uuid4(),
        evaluated_at=datetime.now(timezone.utc),
        decision=evaluation.decision,
        policy=evaluation.policy_id,
        policy_version=evaluation.policy_version,
        reason=evaluation.reason,
        evidence=evaluation.evidence,
        agent=request.agent,
        action=request.action,
        context=request.context,
        trace=evaluation.trace,
    )

    approval = None

    if authorization.decision == "REQUIRE_APPROVAL":
        approval = ApprovalRecord(
            decision_id=authorization.decision_id,
            status="PENDING",
            requested_at=authorization.evaluated_at,
        )

    idempotency_record = None

    if (
        idempotency_key is not None
        and request_fingerprint is not None
    ):
        idempotency_record = IdempotencyRecord(
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
            decision_id=authorization.decision_id,
            created_at=authorization.evaluated_at,
        )

    try:
        store.save_authorization_with_approval(
            authorization=authorization,
            approval=approval,
            idempotency_record=idempotency_record,
        )
    except sqlite3.IntegrityError:
        if (
            idempotency_key is None
            or request_fingerprint is None
        ):
            raise

        existing_authorization = (
            _get_idempotent_authorization(
                store=store,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
            )
        )

        if existing_authorization is None:
            raise

        return existing_authorization

    return authorization


@app.get(
    "/v1/decisions",
    response_model=AuthorizationDecisionPage,
    dependencies=[Depends(require_api_key)],
)
def list_authorization_decisions(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationDecisionPage:
    return AuthorizationDecisionPage(
        items=store.list_decisions(
            limit=limit,
            offset=offset,
        ),
        total=store.count(),
        limit=limit,
        offset=offset,
    )


@app.get(
    "/v1/decisions/{decision_id}",
    response_model=AuthorizationResponse,
    dependencies=[Depends(require_api_key)],
)
def get_authorization_decision(
    decision_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationResponse:
    authorization = store.get(decision_id)

    if authorization is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "decision_not_found",
                "message": (
                    f"Decision '{decision_id}' was not found."
                ),
            },
        )

    return authorization


@app.get(
    "/v1/approvals",
    response_model=ApprovalRequestPage,
    dependencies=[Depends(require_api_key)],
)
def list_approval_requests(
    status: ApprovalStatus | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRequestPage:
    return ApprovalRequestPage(
        items=store.list_approvals(
            status=status,
            limit=limit,
            offset=offset,
        ),
        total=store.count_approvals(status=status),
        limit=limit,
        offset=offset,
    )

@app.get(
    "/v1/approvals/{decision_id}",
    response_model=ApprovalRecord,
    dependencies=[Depends(require_api_key)],
)
def get_approval_request(
    decision_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    approval = store.get_approval(decision_id)

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "approval_not_found",
                "message": (
                    f"Approval for decision "
                    f"'{decision_id}' was not found."
                ),
            },
        )

    return approval


@app.post(
    "/v1/approvals/{decision_id}/approve",
    response_model=ApprovalRecord,
    dependencies=[Depends(require_api_key)],
)
def approve_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    return _resolve_approval_request(
        decision_id=decision_id,
        resolution=resolution,
        status="APPROVED",
        store=store,
    )


@app.post(
    "/v1/approvals/{decision_id}/reject",
    response_model=ApprovalRecord,
    dependencies=[Depends(require_api_key)],
)
def reject_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    return _resolve_approval_request(
        decision_id=decision_id,
        resolution=resolution,
        status="REJECTED",
        store=store,
    )
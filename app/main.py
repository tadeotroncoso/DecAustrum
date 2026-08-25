from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, HTTPException, Query

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


DATABASE_PATH = Path("data/regtrace.db")
evidence_store = EvidenceStore(DATABASE_PATH)


@asynccontextmanager
async def lifespan(_: FastAPI):
    evidence_store.initialize()
    yield


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
    lifespan=lifespan,
)


def get_evidence_store() -> EvidenceStore:
    return evidence_store


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
)
def authorize(
    request: AuthorizationRequest,
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationResponse:
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

    store.save_authorization_with_approval(
        authorization=authorization,
        approval=approval,
    )

    return authorization


@app.get(
    "/v1/decisions",
    response_model=AuthorizationDecisionPage,
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
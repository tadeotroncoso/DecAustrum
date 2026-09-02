import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException

from app.approval_models import ApprovalRecord
from app.authorization_models import (
    AuthorizationRequest,
    AuthorizationResponse,
)
from app.evidence_store import EvidenceStore
from app.exceptions import (
    InvalidPolicyContextError,
    MissingPolicyContextError,
)
from app.idempotency import (
    IdempotencyRecord,
    build_request_fingerprint,
)
from app.policy_engine import evaluate_policy
from app.project_models import Project


def get_idempotent_authorization(
    store: EvidenceStore,
    idempotency_key: str,
    request_fingerprint: str,
    project_id: UUID,
) -> AuthorizationResponse | None:
    existing_record = store.get_idempotency_record(
        project_id=project_id,
        idempotency_key=idempotency_key,
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
        decision_id=existing_record.decision_id,
        project_id=project_id,
    )

    if authorization is None:
        raise RuntimeError(
            "Idempotency record references a missing "
            "authorization decision."
        )

    return authorization


def authorize_request(
    request: AuthorizationRequest,
    idempotency_key: str | None,
    project: Project,
    store: EvidenceStore,
    approval_ttl_seconds: int = 86_400,
) -> AuthorizationResponse:
    request_fingerprint = None

    if idempotency_key is not None:
        request_fingerprint = build_request_fingerprint(
            request
        )

        existing_authorization = (
            get_idempotent_authorization(
                store=store,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                project_id=project.project_id,
            )
        )

        if existing_authorization is not None:
            return existing_authorization

    try:
        evaluation = evaluate_policy(
            request.action,
            request.context,
            policies=store.list_project_policies(
                project.project_id
            ),
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
    except MissingPolicyContextError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "missing_policy_context",
                "message": str(exc),
                "field": exc.field,
                "policy": exc.policy_id,
            },
        ) from exc

    authorization = AuthorizationResponse(
        decision_id=uuid4(),
        project_id=project.project_id,
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
            expires_at=(
                authorization.evaluated_at
                + timedelta(seconds=approval_ttl_seconds)
            ),
        )

    idempotency_record = None

    if (
        idempotency_key is not None
        and request_fingerprint is not None
    ):
        idempotency_record = IdempotencyRecord(
            project_id=project.project_id,
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
            get_idempotent_authorization(
                store=store,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                project_id=project.project_id,
            )
        )

        if existing_authorization is None:
            raise

        return existing_authorization

    return authorization

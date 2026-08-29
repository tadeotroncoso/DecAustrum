import secrets
from datetime import datetime, timezone

from fastapi import HTTPException

from app.audit_models import AuditContext
from app.authorization_models import AuthorizationRequest
from app.evidence_store import EvidenceStore
from app.exceptions import (
    ExecutionGrantAlreadyConsumedError,
    ExecutionGrantExpiredError,
    ExecutionGrantMismatchError,
    InvalidExecutionGrantError,
)
from app.execution_grants import (
    hash_execution_grant_token,
    parse_execution_grant_token,
)
from app.execution_models import (
    ExecutionGrantConsumptionRequest,
    ExecutionGrantConsumptionResponse,
)
from app.idempotency import build_request_fingerprint
from app.project_models import Project


def _invalid_grant(exc: Exception | None = None) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail={
            "code": "invalid_execution_grant",
            "message": "Execution grant is invalid.",
        },
    )


def consume_execution_grant_request(
    *,
    request: ExecutionGrantConsumptionRequest,
    project: Project,
    store: EvidenceStore,
    execution_grant_secret: str,
    consumed_at: datetime | None = None,
) -> ExecutionGrantConsumptionResponse:
    effective_time = consumed_at or datetime.now(timezone.utc)

    try:
        payload = parse_execution_grant_token(
            request.execution_grant,
            execution_grant_secret,
        )
    except (InvalidExecutionGrantError, ValueError) as exc:
        raise _invalid_grant(exc) from exc

    if payload.project_id != project.project_id:
        raise _invalid_grant()

    authorization = store.get(
        decision_id=payload.decision_id,
        project_id=project.project_id,
    )

    if authorization is None:
        raise _invalid_grant()

    immutable_fingerprint = build_request_fingerprint(
        AuthorizationRequest(
            agent=authorization.agent,
            action=authorization.action,
            context=authorization.context,
        )
    )

    if not secrets.compare_digest(
        immutable_fingerprint,
        payload.request_fingerprint,
    ):
        raise _invalid_grant()

    presented_fingerprint = build_request_fingerprint(
        AuthorizationRequest(
            agent=request.agent,
            action=request.action,
            context=request.context,
        )
    )

    try:
        consumed = store.consume_execution_grant(
            payload=payload,
            project_id=project.project_id,
            token_hash=hash_execution_grant_token(
                request.execution_grant
            ),
            request_fingerprint=presented_fingerprint,
            consumed_at=effective_time,
            consumed_by=request.consumed_by,
            audit_context=AuditContext(
                actor_type="PROJECT",
                actor_id=request.consumed_by,
                reason="Approved action execution consumed.",
            ),
        )
    except InvalidExecutionGrantError as exc:
        raise _invalid_grant(exc) from exc
    except ExecutionGrantMismatchError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "execution_grant_mismatch",
                "message": str(exc),
            },
        ) from exc
    except ExecutionGrantAlreadyConsumedError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "execution_grant_already_consumed",
                "message": str(exc),
            },
        ) from exc
    except ExecutionGrantExpiredError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "execution_grant_expired",
                "message": str(exc),
            },
        ) from exc

    return ExecutionGrantConsumptionResponse(
        grant_id=consumed.grant_id,
        decision_id=consumed.decision_id,
        consumed_at=consumed.consumed_at,
        consumed_by=consumed.consumed_by,
        agent=request.agent,
        action=request.action,
    )

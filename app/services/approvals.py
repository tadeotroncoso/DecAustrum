import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException

from app.approval_models import (
    ApprovalGrantResponse,
    ApprovalRecord,
    ApprovalResolutionRequest,
    ApprovalResolutionStatus,
)
from app.audit_models import AuditContext
from app.authorization_models import AuthorizationRequest
from app.evidence_store import EvidenceStore
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
)
from app.execution_grants import (
    build_execution_grant_token,
    hash_execution_grant_token,
)
from app.execution_models import (
    ExecutionGrantPayload,
    ExecutionGrantRecord,
)
from app.idempotency import build_request_fingerprint


def resolve_approval_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    status: ApprovalResolutionStatus,
    project_id: UUID,
    store: EvidenceStore,
) -> ApprovalRecord:
    try:
        return store.resolve_approval(
            decision_id=decision_id,
            project_id=project_id,
            status=status,
            resolved_by=resolution.resolved_by,
            resolved_at=datetime.now(timezone.utc),
            audit_context=AuditContext(
                actor_type="PROJECT",
                actor_id=resolution.resolved_by,
                reason=resolution.reason,
            ),
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
    except ApprovalExpiredError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval_expired",
                "message": str(exc),
            },
        ) from exc


def approve_approval_request(
    *,
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    project_id: UUID,
    store: EvidenceStore,
    execution_grant_secret: str,
    execution_grant_ttl_seconds: int,
    approved_at: datetime | None = None,
) -> ApprovalGrantResponse:
    effective_time = approved_at or datetime.now(timezone.utc)
    approval = store.get_approval(
        decision_id=decision_id,
        project_id=project_id,
    )

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "approval_not_found",
                "message": (
                    f"Approval for decision '{decision_id}' "
                    "was not found."
                ),
            },
        )

    if approval.status == "EXPIRED":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval_expired",
                "message": (
                    f"Approval for decision '{decision_id}' "
                    "has expired."
                ),
            },
        )

    if approval.status == "APPROVED":
        existing_grant = (
            store.get_execution_grant_for_decision(
                decision_id=decision_id,
                project_id=project_id,
            )
        )

        if (
            existing_grant is not None
            and existing_grant.status == "ACTIVE"
            and existing_grant.expires_at > effective_time
        ):
            token = build_execution_grant_token(
                existing_grant,
                execution_grant_secret,
            )
            return ApprovalGrantResponse(
                **approval.model_dump(),
                execution_grant=token,
                grant_id=existing_grant.grant_id,
                grant_expires_at=existing_grant.expires_at,
            )

        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval_already_resolved",
                "message": (
                    f"Approval for decision '{decision_id}' "
                    "is already APPROVED."
                ),
                "current_status": "APPROVED",
            },
        )

    if approval.status != "PENDING":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval_already_resolved",
                "message": (
                    f"Approval for decision '{decision_id}' "
                    f"is already {approval.status}."
                ),
                "current_status": approval.status,
            },
        )

    authorization = store.get(
        decision_id=decision_id,
        project_id=project_id,
    )

    if authorization is None:
        raise RuntimeError(
            "Approval references a missing authorization decision."
        )

    request_fingerprint = build_request_fingerprint(
        AuthorizationRequest(
            agent=authorization.agent,
            action=authorization.action,
            context=authorization.context,
        )
    )
    payload = ExecutionGrantPayload(
        grant_id=uuid4(),
        decision_id=decision_id,
        project_id=project_id,
        request_fingerprint=request_fingerprint,
        issued_at=effective_time,
        expires_at=(
            effective_time
            + timedelta(seconds=execution_grant_ttl_seconds)
        ),
    )
    token = build_execution_grant_token(
        payload,
        execution_grant_secret,
    )
    grant = ExecutionGrantRecord(
        **payload.model_dump(),
        status="ACTIVE",
        token_hash=hash_execution_grant_token(token),
    )

    try:
        approved, persisted_grant = (
            store.approve_approval_with_grant(
                decision_id=decision_id,
                project_id=project_id,
                resolved_by=resolution.resolved_by,
                resolved_at=effective_time,
                grant=grant,
                audit_context=AuditContext(
                    actor_type="PROJECT",
                    actor_id=resolution.resolved_by,
                    reason=resolution.reason,
                ),
            )
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "approval_not_found",
                "message": str(exc),
            },
        ) from exc
    except ApprovalExpiredError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval_expired",
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
    except sqlite3.IntegrityError as exc:
        concurrent_approval = store.get_approval(
            decision_id=decision_id,
            project_id=project_id,
        )
        concurrent_grant = (
            store.get_execution_grant_for_decision(
                decision_id=decision_id,
                project_id=project_id,
            )
        )

        if concurrent_approval is None:
            raise

        if concurrent_approval.status == "EXPIRED":
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "approval_expired",
                    "message": (
                        f"Approval for decision '{decision_id}' "
                        "has expired."
                    ),
                },
            ) from exc

        if (
            concurrent_approval.status != "APPROVED"
            or concurrent_grant is None
            or concurrent_grant.status != "ACTIVE"
            or concurrent_grant.expires_at <= effective_time
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "approval_already_resolved",
                    "message": (
                        f"Approval for decision '{decision_id}' "
                        f"is already {concurrent_approval.status}."
                    ),
                    "current_status": concurrent_approval.status,
                },
            ) from exc

        approved = concurrent_approval
        persisted_grant = concurrent_grant

    persisted_token = build_execution_grant_token(
        persisted_grant,
        execution_grant_secret,
    )

    if not secrets.compare_digest(
        persisted_grant.token_hash,
        hash_execution_grant_token(persisted_token),
    ):
        raise RuntimeError(
            "Persisted execution grant cannot be regenerated."
        )

    return ApprovalGrantResponse(
        **approved.model_dump(),
        execution_grant=persisted_token,
        grant_id=persisted_grant.grant_id,
        grant_expires_at=persisted_grant.expires_at,
    )

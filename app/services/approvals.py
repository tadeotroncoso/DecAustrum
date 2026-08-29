from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException

from app.audit_models import AuditContext
from app.approval_models import (
    ApprovalRecord,
    ApprovalResolutionRequest,
    ApprovalResolutionStatus,
)
from app.evidence_store import EvidenceStore
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
)


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

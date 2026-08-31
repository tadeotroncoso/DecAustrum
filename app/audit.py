from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel

from app.audit_models import (
    AdministrativeAuditEvent,
    AuditAction,
    AuditContext,
    AuditResourceType,
)


SYSTEM_BOOTSTRAP_AUDIT_CONTEXT = AuditContext(
    actor_type="SYSTEM",
    actor_id="decaustrum-bootstrap",
    reason="DecAustrum system bootstrap.",
)


def audit_snapshot(
    value: BaseModel | dict[str, Any] | None,
) -> dict[str, Any] | None:
    if value is None:
        return None

    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")

    return value


def build_audit_event(
    *,
    occurred_at: datetime,
    project_id: UUID,
    context: AuditContext,
    action: AuditAction,
    resource_type: AuditResourceType,
    resource_id: str,
    before: BaseModel | dict[str, Any] | None = None,
    after: BaseModel | dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> AdministrativeAuditEvent:
    return AdministrativeAuditEvent(
        event_id=uuid4(),
        occurred_at=occurred_at,
        project_id=project_id,
        actor_type=context.actor_type,
        actor_id=context.actor_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        reason=context.reason,
        before=audit_snapshot(before),
        after=audit_snapshot(after),
        metadata=metadata or {},
    )

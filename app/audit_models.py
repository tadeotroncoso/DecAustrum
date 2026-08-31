from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    field_validator,
)

AuditActorType = Literal[
    "ADMIN",
    "PROJECT",
    "SYSTEM",
]

AuditAction = Literal[
    "PROJECT_CREATED",
    "PROJECT_STATUS_CHANGED",
    "API_KEY_CREATED",
    "API_KEY_REVOKED",
    "POLICY_CREATED",
    "POLICY_UPDATED",
    "POLICY_DISABLED",
    "POLICY_ROLLED_BACK",
    "APPROVAL_RESOLVED",
    "APPROVAL_EXPIRED",
    "EXECUTION_GRANT_ISSUED",
    "EXECUTION_GRANT_CONSUMED",
    "EXECUTION_GRANT_EXPIRED",
    "WEBHOOK_SUBSCRIPTION_CREATED",
    "WEBHOOK_SUBSCRIPTION_DISABLED",
    "WEBHOOK_SECRET_ROTATED",
    "WEBHOOK_REDELIVERY_REQUESTED",
]

AuditResourceType = Literal[
    "PROJECT",
    "API_KEY",
    "POLICY",
    "APPROVAL",
    "EXECUTION_GRANT",
    "WEBHOOK_SUBSCRIPTION",
    "WEBHOOK_DELIVERY",
]

AuditActorIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=200,
    ),
]

AuditReason = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=500,
    ),
]

AuditResourceIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=200,
    ),
]


class AuditContext(BaseModel):
    actor_type: AuditActorType
    actor_id: AuditActorIdentifier
    reason: AuditReason | None = None


class AdministrativeAuditEvent(BaseModel):
    event_id: UUID
    occurred_at: datetime
    project_id: UUID
    actor_type: AuditActorType
    actor_id: AuditActorIdentifier
    action: AuditAction
    resource_type: AuditResourceType
    resource_id: AuditResourceIdentifier
    reason: AuditReason | None = None
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("occurred_at")
    @classmethod
    def require_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        if value.tzinfo is None:
            raise ValueError("occurred_at must include a timezone.")

        return value.astimezone(timezone.utc)


class AdministrativeAuditEventPage(BaseModel):
    items: list[AdministrativeAuditEvent]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)

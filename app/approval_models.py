from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

ApprovalStatus = Literal[
    "PENDING",
    "APPROVED",
    "REJECTED",
    "EXPIRED",
]

ApprovalResolutionStatus = Literal[
    "APPROVED",
    "REJECTED",
]

class ApprovalRecord(BaseModel):
    decision_id: UUID
    status: ApprovalStatus
    requested_at: datetime
    expires_at: datetime | None = None
    resolved_at: datetime | None = None
    resolved_by: str | None = None

    @field_validator(
        "requested_at",
        "expires_at",
        "resolved_at",
    )
    @classmethod
    def require_timezone(
        cls,
        value: datetime | None,
        info,
    ) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None:
            raise ValueError(
                f"{info.field_name} must include a timezone."
            )

        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_lifecycle(self):
        if (
            self.expires_at is not None
            and self.expires_at <= self.requested_at
        ):
            raise ValueError(
                "expires_at must be later than requested_at."
            )

        if self.status == "PENDING" and (
            self.resolved_at is not None
            or self.resolved_by is not None
        ):
            raise ValueError(
                "Pending approval cannot contain resolution data."
            )

        if self.status != "PENDING" and (
            self.resolved_at is None
            or self.resolved_by is None
        ):
            raise ValueError(
                "Terminal approval requires resolution data."
            )

        if (
            self.resolved_at is not None
            and self.resolved_at < self.requested_at
        ):
            raise ValueError(
                "resolved_at cannot precede requested_at."
            )

        if (
            self.status == "EXPIRED"
            and self.expires_at is not None
            and self.resolved_at is not None
            and self.resolved_at < self.expires_at
        ):
            raise ValueError(
                "Expired approval cannot resolve before expires_at."
            )

        return self


class ApprovalGrantResponse(ApprovalRecord):
    execution_grant: str = Field(
        min_length=1,
        repr=False,
    )
    grant_id: UUID
    grant_expires_at: datetime

    @field_validator("grant_expires_at")
    @classmethod
    def require_grant_expiry_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        if value.tzinfo is None:
            raise ValueError(
                "grant_expires_at must include a timezone."
            )

        return value.astimezone(timezone.utc)

class ApprovalRequestPage(BaseModel):
    items: list[ApprovalRecord]
    total: int
    limit: int
    offset: int

class ApprovalResolutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=500,
        ),
    ] | None = None

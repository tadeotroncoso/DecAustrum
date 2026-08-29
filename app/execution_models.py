from datetime import datetime, timezone
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


ExecutionGrantStatus = Literal[
    "ACTIVE",
    "CONSUMED",
    "EXPIRED",
]

Sha256Digest = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-f]{64}$",
    ),
]

ConsumerIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=200,
    ),
]


class ExecutionGrantPayload(BaseModel):
    version: Literal[1] = 1
    grant_id: UUID
    decision_id: UUID
    project_id: UUID
    request_fingerprint: Sha256Digest
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(
        cls,
        value: datetime,
        info,
    ) -> datetime:
        if value.tzinfo is None:
            raise ValueError(
                f"{info.field_name} must include a timezone."
            )

        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_expiry(self):
        if self.expires_at <= self.issued_at:
            raise ValueError(
                "expires_at must be later than issued_at."
            )

        return self


class ExecutionGrantRecord(ExecutionGrantPayload):
    status: ExecutionGrantStatus = "ACTIVE"
    request_fingerprint: Sha256Digest = Field(
        exclude=True,
        repr=False,
    )
    token_hash: Sha256Digest = Field(exclude=True, repr=False)
    consumed_at: datetime | None = None
    consumed_by: ConsumerIdentifier | None = None

    @field_validator("consumed_at")
    @classmethod
    def require_consumed_at_timezone(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None

        if value.tzinfo is None:
            raise ValueError(
                "consumed_at must include a timezone."
            )

        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_status(self):
        if self.status == "CONSUMED":
            if self.consumed_at is None or self.consumed_by is None:
                raise ValueError(
                    "Consumed grant requires consumption data."
                )
            if self.consumed_at >= self.expires_at:
                raise ValueError(
                    "Consumed grant must be used before expires_at."
                )
        elif self.consumed_at is not None or self.consumed_by is not None:
            raise ValueError(
                "Unconsumed grant cannot contain consumption data."
            )

        return self


class ExecutionGrantConsumptionRequest(BaseModel):
    execution_grant: str = Field(
        min_length=1,
        max_length=4096,
        exclude=True,
        repr=False,
    )
    agent: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1),
    ]
    action: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1),
    ]
    context: dict[str, Any]
    consumed_by: ConsumerIdentifier


class ExecutionGrantConsumptionResponse(BaseModel):
    authorized: Literal[True] = True
    grant_id: UUID
    decision_id: UUID
    consumed_at: datetime
    consumed_by: ConsumerIdentifier
    agent: str
    action: str

    @field_validator("consumed_at")
    @classmethod
    def require_response_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        if value.tzinfo is None:
            raise ValueError(
                "consumed_at must include a timezone."
            )

        return value.astimezone(timezone.utc)

from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, StringConstraints, field_validator

from app.decision_models import (
    PolicyEvidence,
    PolicyTraceEntry,
)
from app.json_values import validate_json_value
from app.policy_types import Decision

NonEmptyString = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
    ),
]


class AuthorizationRequest(BaseModel):
    agent: NonEmptyString
    action: NonEmptyString
    context: dict[str, Any]

    @field_validator("context", mode="before")
    @classmethod
    def require_strict_json_context(cls, value: Any) -> Any:
        return validate_json_value(value, name="context")


class AuthorizationResponse(BaseModel):
    decision_id: UUID
    project_id: UUID
    evaluated_at: datetime
    decision: Decision
    policy: str | None
    policy_version: int | None
    reason: str
    evidence: PolicyEvidence | None
    agent: str
    action: str
    context: dict[str, Any]
    trace: list[PolicyTraceEntry]

    @field_validator("context", mode="before")
    @classmethod
    def require_strict_json_context(cls, value: Any) -> Any:
        return validate_json_value(value, name="context")

class AuthorizationDecisionPage(BaseModel):
    items: list[AuthorizationResponse]
    total: int
    limit: int
    offset: int

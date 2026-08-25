from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from app.decision_models import PolicyEvidence
from app.policy_types import Decision

from pydantic import BaseModel, StringConstraints



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


class AuthorizationResponse(BaseModel):
    decision_id: UUID
    evaluated_at: datetime
    decision: Decision
    policy: str | None
    policy_version: int | None
    reason: str
    evidence: PolicyEvidence | None
    agent: str
    action: str
    context: dict[str, Any]

class AuthorizationDecisionPage(BaseModel):
    items: list[AuthorizationResponse]
    total: int
    limit: int
    offset: int
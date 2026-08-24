from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, StringConstraints

from app.decision_models import ConditionEvidence, Decision


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
    evidence: ConditionEvidence | None
    agent: str
    action: str
    context: dict[str, Any]

class AuthorizationDecisionPage(BaseModel):
    items: list[AuthorizationResponse]
    total: int
    limit: int
    offset: int
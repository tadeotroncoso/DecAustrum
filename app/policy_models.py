from typing import Any

from pydantic import BaseModel, Field

from app.policy_types import (
    ConditionMatch,
    Decision,
    Operator,
)


class PolicyCondition(BaseModel):
    field: str
    operator: Operator
    value: Any


class Policy(BaseModel):
    id: str
    version: int = Field(ge=1)
    action: str
    match: ConditionMatch
    conditions: list[PolicyCondition] = Field(min_length=1)
    decision: Decision
    reason: str
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.decision_models import Decision


class PolicyCondition(BaseModel):
    field: str
    operator: Literal[
        "greater_than",
        "less_than",
        "equals",
        "not_equals",
    ]
    value: Any


class Policy(BaseModel):
    id: str
    version: int = Field(ge=1)
    action: str
    condition: PolicyCondition
    decision: Decision
    reason: str
from typing import Any, Literal

from pydantic import BaseModel

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
    action: str
    condition: PolicyCondition
    decision: Decision
    reason: str
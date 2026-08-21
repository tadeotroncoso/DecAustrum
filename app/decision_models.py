from typing import Any, Literal

from pydantic import BaseModel


Decision = Literal[
    "ALLOW",
    "REQUIRE_APPROVAL",
    "DENY",
]

class ConditionEvidence(BaseModel):
    field: str
    operator: str
    actual_value: Any
    expected_value: Any


class PolicyEvaluation(BaseModel):
    decision: Decision
    policy_id: str | None = None
    reason: str
    evidence: ConditionEvidence | None = None
    policy_version: int | None = None
from typing import Any

from pydantic import BaseModel, field_validator

from app.json_values import validate_json_value
from app.policy_types import (
    ConditionMatch,
    Decision,
    Operator,
)


class ConditionEvidence(BaseModel):
    field: str
    operator: Operator
    actual_value: Any
    expected_value: Any
    matched: bool

    @field_validator("actual_value", "expected_value", mode="before")
    @classmethod
    def require_strict_json_values(
        cls,
        value: Any,
        info,
    ) -> Any:
        return validate_json_value(value, name=info.field_name)


class PolicyEvidence(BaseModel):
    match: ConditionMatch
    conditions: list[ConditionEvidence]

class PolicyTraceEntry(BaseModel):
    policy_id: str
    policy_version: int
    decision: Decision
    reason: str
    matched: bool
    evidence: PolicyEvidence


class PolicyEvaluation(BaseModel):
    decision: Decision
    policy_id: str | None = None
    policy_version: int | None = None
    reason: str
    evidence: PolicyEvidence | None = None
    trace: list[PolicyTraceEntry]

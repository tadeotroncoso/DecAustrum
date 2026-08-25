from typing import Any

from pydantic import BaseModel

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


class PolicyEvidence(BaseModel):
    match: ConditionMatch
    conditions: list[ConditionEvidence]


class PolicyEvaluation(BaseModel):
    decision: Decision
    policy_id: str | None = None
    policy_version: int | None = None
    reason: str
    evidence: PolicyEvidence | None = None
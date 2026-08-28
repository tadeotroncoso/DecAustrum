from datetime import datetime
from typing import Any
from uuid import UUID

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


class PolicyPage(BaseModel):
    items: list[Policy]
    total: int


class ProjectPolicyConfiguration(BaseModel):
    project_id: UUID
    policy: Policy
    enabled: bool
    updated_at: datetime


class ProjectPolicyConfigurationPage(BaseModel):
    items: list[ProjectPolicyConfiguration]
    total: int

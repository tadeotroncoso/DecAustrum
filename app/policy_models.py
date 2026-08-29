from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

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


PolicyVersionChangeType = Literal[
    "CREATED",
    "UPDATED",
    "ROLLBACK",
    "MIGRATED",
]


class ProjectPolicyVersion(BaseModel):
    project_id: UUID
    policy_id: str
    version: int = Field(ge=1)
    policy: Policy
    change_type: PolicyVersionChangeType
    source_version: int | None = Field(default=None, ge=1)
    created_at: datetime

    @model_validator(mode="after")
    def validate_version_identity(
        self,
    ) -> "ProjectPolicyVersion":
        if self.policy.id != self.policy_id:
            raise ValueError(
                "Historical policy ID must match policy_id."
            )

        if self.policy.version != self.version:
            raise ValueError(
                "Historical policy version must match version."
            )

        if (
            self.change_type == "ROLLBACK"
            and self.source_version is None
        ):
            raise ValueError(
                "Rollback versions require source_version."
            )

        if (
            self.change_type != "ROLLBACK"
            and self.source_version is not None
        ):
            raise ValueError(
                "Only rollback versions may have source_version."
            )

        return self


class ProjectPolicyVersionPage(BaseModel):
    items: list[ProjectPolicyVersion]
    total: int
    limit: int
    offset: int


class PolicyRollbackRequest(BaseModel):
    version: int = Field(ge=1)

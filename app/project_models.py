from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    model_validator,
)

DEFAULT_PROJECT_ID = UUID(
    "00000000-0000-0000-0000-000000000001"
)

DEFAULT_PROJECT_NAME = "Default Project"


ProjectStatus = Literal[
    "ACTIVE",
    "DISABLED",
]

ProjectName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=100,
    ),
]


class Project(BaseModel):
    project_id: UUID
    name: ProjectName
    status: ProjectStatus = "ACTIVE"
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def default_updated_at_to_created_at(
        cls,
        data: Any,
    ) -> Any:
        if (
            isinstance(data, dict)
            and "updated_at" not in data
            and "created_at" in data
        ):
            return {
                **data,
                "updated_at": data["created_at"],
            }

        return data


class ProjectCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ProjectName


class ProjectStatusUpdateRequest(BaseModel):
    status: ProjectStatus


class ProjectPage(BaseModel):
    items: list[Project]
    total: int
    limit: int
    offset: int


class ProjectProvisioningResponse(BaseModel):
    project: Project
    api_key: str

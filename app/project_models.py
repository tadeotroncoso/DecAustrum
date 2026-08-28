from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, StringConstraints

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


class ProjectCreateRequest(BaseModel):
    name: ProjectName


class ProjectProvisioningResponse(BaseModel):
    project: Project
    api_key: str

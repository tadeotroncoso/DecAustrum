from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, StringConstraints


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
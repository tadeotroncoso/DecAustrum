from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, StringConstraints


ApprovalStatus = Literal[
    "PENDING",
    "APPROVED",
    "REJECTED",
]

ApprovalResolutionStatus = Literal[
    "APPROVED",
    "REJECTED",
]

class ApprovalRecord(BaseModel):
    decision_id: UUID
    status: ApprovalStatus
    requested_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None

ResolverIdentifier = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
    ),
]


class ApprovalResolutionRequest(BaseModel):
    resolved_by: ResolverIdentifier
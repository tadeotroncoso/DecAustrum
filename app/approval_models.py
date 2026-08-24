from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel


ApprovalStatus = Literal[
    "PENDING",
    "APPROVED",
    "REJECTED",
]


class ApprovalRecord(BaseModel):
    decision_id: UUID
    status: ApprovalStatus
    requested_at: datetime
    resolved_at: datetime | None = None
    resolved_by: str | None = None
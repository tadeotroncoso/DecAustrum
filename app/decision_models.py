from typing import Literal

from pydantic import BaseModel


Decision = Literal[
    "ALLOW",
    "REQUIRE_APPROVAL",
    "DENY",
]


class PolicyEvaluation(BaseModel):
    decision: Decision
    policy_id: str | None = None
    reason: str
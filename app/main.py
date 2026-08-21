from typing import Annotated, Any
from app.policy_engine import evaluate_policy
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, StringConstraints
from app.decision_models import ConditionEvidence, Decision
from app.exceptions import InvalidPolicyContextError
from datetime import datetime, timezone
from uuid import UUID, uuid4


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
)

NonEmptyString = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
    ),
]

class AuthorizationRequest(BaseModel):
    agent: NonEmptyString
    action: NonEmptyString
    context: dict[str, Any]

class AuthorizationResponse(BaseModel):
    decision_id: UUID
    evaluated_at: datetime
    decision: Decision
    policy: str | None
    policy_version: int | None
    reason: str
    evidence: ConditionEvidence | None
    agent: str
    action: str
    context: dict[str, Any]

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post(
    "/v1/authorize",
    response_model=AuthorizationResponse,
)
def authorize(
    request: AuthorizationRequest,
) -> AuthorizationResponse:
    try:
        evaluation = evaluate_policy(
            request.action,
            request.context,
        )
    except InvalidPolicyContextError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_policy_context",
                "message": str(exc),
                "field": exc.field,
                "operator": exc.operator,
            },
        ) from exc

    return AuthorizationResponse(
        decision_id=uuid4(),
        evaluated_at=datetime.now(timezone.utc),
        decision=evaluation.decision,
        policy=evaluation.policy_id,
        policy_version=evaluation.policy_version,
        reason=evaluation.reason,
        evidence=evaluation.evidence,
        agent=request.agent,
        action=request.action,
        context=request.context,
    )
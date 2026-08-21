from typing import Any
from app.policy_engine import evaluate_policy
from fastapi import FastAPI
from pydantic import BaseModel
from app.decision_models import ConditionEvidence, Decision


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
)


class AuthorizationRequest(BaseModel):
    agent: str
    action: str
    context: dict[str, Any]

class AuthorizationResponse(BaseModel):
    decision: Decision
    policy: str | None
    reason: str
    evidence: ConditionEvidence | None
    agent: str
    action: str
    context: dict[str, Any]

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/v1/authorize", response_model=AuthorizationResponse,)
def authorize(
    request: AuthorizationRequest,
    ) -> AuthorizationResponse:
    evaluation = evaluate_policy(
    request.action,
    request.context,
    )   

    return AuthorizationResponse(
        decision=evaluation.decision,
        policy=evaluation.policy_id,
        reason=evaluation.reason,
        evidence=evaluation.evidence,
        agent=request.agent,
        action=request.action,
        context=request.context,
    )
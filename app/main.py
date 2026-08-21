from typing import Any
from app.policy_engine import evaluate_policy
from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
)


class AuthorizationRequest(BaseModel):
    agent: str
    action: str
    context: dict[str, Any]


@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/v1/authorize")
def authorize(request: AuthorizationRequest):
    evaluation = evaluate_policy(
    request.action,
    request.context,
    )   

    return {
        "decision": evaluation.decision,
        "policy": evaluation.policy_id,
        "reason": evaluation.reason,
        "agent": request.agent,
        "action": request.action,
        "context": request.context,
        "evidence": (
            evaluation.evidence.model_dump()
            if evaluation.evidence is not None
            else None
        ),
    }
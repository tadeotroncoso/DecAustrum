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
    decision, policy_id = evaluate_policy(
        request.action,
        request.context,
    )

    return {
        "decision": decision,
        "policy": policy_id,
        "agent": request.agent,
        "action": request.action,
        "context": request.context,
    }
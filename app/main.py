from typing import Any

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
    if (
        request.action == "refund_payment"
        and request.context.get("amount", 0) > 500
    ):
        decision = "REQUIRE_APPROVAL"
    else:
        decision = "ALLOW"

    return {
        "decision": decision,
        "agent": request.agent,
        "action": request.action,
        "context": request.context,
    }
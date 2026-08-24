from app.policy_engine import evaluate_policy
from fastapi import FastAPI, HTTPException


from app.exceptions import InvalidPolicyContextError
from datetime import datetime, timezone
from uuid import uuid4
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException

from app.evidence_store import EvidenceStore


from app.authorization_models import (
    AuthorizationRequest,
    AuthorizationResponse,
)

DATABASE_PATH = Path("data/regtrace.db")
evidence_store = EvidenceStore(DATABASE_PATH)


@asynccontextmanager
async def lifespan(_: FastAPI):
    evidence_store.initialize()
    yield


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
    lifespan=lifespan,
)


def get_evidence_store() -> EvidenceStore:
    return evidence_store

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post(
    "/v1/authorize",
    response_model=AuthorizationResponse,
)
def authorize(
    request: AuthorizationRequest,
    store: EvidenceStore = Depends(get_evidence_store),
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

    authorization = AuthorizationResponse(
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

    store.save(authorization)

    return authorization
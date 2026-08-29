from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.dependencies import (
    get_evidence_store,
    get_metrics_registry,
)
from app.evidence_store import EvidenceStore
from app.observability import MetricsRegistry


router = APIRouter()


@router.get("/health")
def health_check():
    return {"status": "ok"}


@router.get("/health/live")
def liveness_check():
    return {"status": "ok"}


@router.get(
    "/health/ready",
    response_model=None,
)
def readiness_check(
    store: EvidenceStore = Depends(get_evidence_store),
    metrics: MetricsRegistry = Depends(get_metrics_registry),
) -> JSONResponse:
    try:
        ready = store.check_readiness()
    except Exception:
        ready = False

    metrics.set_ready(ready)

    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ok" if ready else "unavailable",
        },
    )

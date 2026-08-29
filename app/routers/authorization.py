from typing import Annotated

from fastapi import APIRouter, Depends, Header

from app.authorization_models import (
    AuthorizationRequest,
    AuthorizationResponse,
)
from app.dependencies import (
    get_authenticated_project,
    get_evidence_store,
    get_metrics_registry,
)
from app.evidence_store import EvidenceStore
from app.observability import MetricsRegistry
from app.project_models import Project
from app.services.authorization import authorize_request


router = APIRouter()


@router.post(
    "/v1/authorize",
    response_model=AuthorizationResponse,
)
def authorize(
    request: AuthorizationRequest,
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            min_length=1,
            max_length=255,
        ),
    ] = None,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
    metrics: MetricsRegistry = Depends(get_metrics_registry),
) -> AuthorizationResponse:
    authorization = authorize_request(
        request=request,
        idempotency_key=idempotency_key,
        project=project,
        store=store,
    )
    metrics.record_authorization_decision(
        authorization.decision
    )
    return authorization

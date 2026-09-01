from fastapi import APIRouter, Depends

from app.dependencies import (
    get_evidence_store,
    get_execution_grant_secret,
    get_runtime_project,
)
from app.evidence_store import EvidenceStore
from app.execution_models import (
    ExecutionGrantConsumptionRequest,
    ExecutionGrantConsumptionResponse,
)
from app.project_models import Project
from app.services.execution_grants import (
    consume_execution_grant_request,
)

router = APIRouter()


@router.post(
    "/v1/execution-grants/consume",
    response_model=ExecutionGrantConsumptionResponse,
)
def consume_execution_grant(
    request: ExecutionGrantConsumptionRequest,
    project: Project = Depends(get_runtime_project),
    store: EvidenceStore = Depends(get_evidence_store),
    execution_grant_secret: str = Depends(
        get_execution_grant_secret
    ),
) -> ExecutionGrantConsumptionResponse:
    return consume_execution_grant_request(
        request=request,
        project=project,
        store=store,
        execution_grant_secret=execution_grant_secret,
    )

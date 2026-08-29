from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.authorization_models import (
    AuthorizationDecisionPage,
    AuthorizationResponse,
)
from app.dependencies import (
    get_authenticated_project,
    get_evidence_store,
    require_admin_access,
)
from app.evidence_store import EvidenceStore
from app.project_models import Project
from app.routers.search import DecisionSearchDependency
from app.services.projects import get_project_or_404


router = APIRouter()


@router.get(
    "/v1/decisions",
    response_model=AuthorizationDecisionPage,
)
def list_authorization_decisions(
    filters: DecisionSearchDependency,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationDecisionPage:
    return AuthorizationDecisionPage(
        items=store.search_decisions(
            project_id=project.project_id,
            filters=filters,
            limit=limit,
            offset=offset,
        ),
        total=store.count_searched_decisions(
            project_id=project.project_id,
            filters=filters,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/v1/admin/projects/{project_id}/decisions",
    response_model=AuthorizationDecisionPage,
    dependencies=[Depends(require_admin_access)],
)
def list_managed_project_authorization_decisions(
    project_id: UUID,
    filters: DecisionSearchDependency,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationDecisionPage:
    get_project_or_404(project_id=project_id, store=store)

    return AuthorizationDecisionPage(
        items=store.search_decisions(
            project_id=project_id,
            filters=filters,
            limit=limit,
            offset=offset,
        ),
        total=store.count_searched_decisions(
            project_id=project_id,
            filters=filters,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/v1/decisions/{decision_id}",
    response_model=AuthorizationResponse,
)
def get_authorization_decision(
    decision_id: UUID,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationResponse:
    authorization = store.get(
        decision_id=decision_id,
        project_id=project.project_id,
    )

    if authorization is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "decision_not_found",
                "message": (
                    f"Decision '{decision_id}' was not found."
                ),
            },
        )

    return authorization

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.authorization_models import (
    AuthorizationDecisionPage,
    AuthorizationResponse,
)
from app.dependencies import (
    get_authenticated_project,
    get_evidence_store,
)
from app.evidence_store import EvidenceStore
from app.project_models import Project


router = APIRouter()


@router.get(
    "/v1/decisions",
    response_model=AuthorizationDecisionPage,
)
def list_authorization_decisions(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationDecisionPage:
    return AuthorizationDecisionPage(
        items=store.list_decisions(
            project_id=project.project_id,
            limit=limit,
            offset=offset,
        ),
        total=store.count(
            project_id=project.project_id
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

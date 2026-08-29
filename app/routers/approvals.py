from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.approval_models import (
    ApprovalRecord,
    ApprovalRequestPage,
    ApprovalResolutionRequest,
    ApprovalStatus,
)
from app.dependencies import (
    get_authenticated_project,
    get_evidence_store,
)
from app.evidence_store import EvidenceStore
from app.project_models import Project
from app.services.approvals import resolve_approval_request


router = APIRouter()


@router.get(
    "/v1/approvals",
    response_model=ApprovalRequestPage,
)
def list_approval_requests(
    status: ApprovalStatus | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRequestPage:
    return ApprovalRequestPage(
        items=store.list_approvals(
            project_id=project.project_id,
            status=status,
            limit=limit,
            offset=offset,
        ),
        total=store.count_approvals(
            project_id=project.project_id,
            status=status,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/v1/approvals/{decision_id}",
    response_model=ApprovalRecord,
)
def get_approval_request(
    decision_id: UUID,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    approval = store.get_approval(
        decision_id=decision_id,
        project_id=project.project_id,
    )

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "approval_not_found",
                "message": (
                    f"Approval for decision "
                    f"'{decision_id}' was not found."
                ),
            },
        )

    return approval


@router.post(
    "/v1/approvals/{decision_id}/approve",
    response_model=ApprovalRecord,
)
def approve_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    return resolve_approval_request(
        decision_id=decision_id,
        resolution=resolution,
        status="APPROVED",
        project_id=project.project_id,
        store=store,
    )


@router.post(
    "/v1/approvals/{decision_id}/reject",
    response_model=ApprovalRecord,
)
def reject_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    return resolve_approval_request(
        decision_id=decision_id,
        resolution=resolution,
        status="REJECTED",
        project_id=project.project_id,
        store=store,
    )

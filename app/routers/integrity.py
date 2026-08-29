from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.dependencies import (
    get_authenticated_project,
    get_evidence_store,
    require_admin_access,
)
from app.evidence_store import EvidenceStore
from app.integrity_models import (
    DecisionIntegrityProof,
    DecisionIntegrityProofPage,
    DecisionIntegrityVerification,
    Sha256Digest,
    VerifiableDecisionRecord,
)
from app.project_models import Project
from app.services.integrity import (
    get_decision_integrity_or_404,
    get_verifiable_decision_or_404,
)
from app.services.projects import get_project_or_404


router = APIRouter()

ExpectedHeadHashQuery = Annotated[
    Sha256Digest | None,
    Query(
        description=(
            "Previously trusted chain head used as an external "
            "checkpoint."
        ),
    ),
]


@router.get(
    "/v1/integrity",
    response_model=DecisionIntegrityProofPage,
)
def list_decision_integrity_records(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> DecisionIntegrityProofPage:
    return DecisionIntegrityProofPage(
        items=store.list_decision_integrity_records(
            project_id=project.project_id,
            limit=limit,
            offset=offset,
        ),
        total=store.count_decision_integrity_records(
            project_id=project.project_id,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/v1/integrity/verify",
    response_model=DecisionIntegrityVerification,
)
def verify_authenticated_project_integrity(
    expected_head_hash: ExpectedHeadHashQuery = None,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> DecisionIntegrityVerification:
    return store.verify_decision_integrity(
        project_id=project.project_id,
        expected_head_hash=expected_head_hash,
    )


@router.get(
    "/v1/decisions/{decision_id}/integrity",
    response_model=DecisionIntegrityProof,
)
def get_decision_integrity(
    decision_id: UUID,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> DecisionIntegrityProof:
    return get_decision_integrity_or_404(
        decision_id=decision_id,
        project_id=project.project_id,
        store=store,
    )


@router.get(
    "/v1/decisions/{decision_id}/evidence",
    response_model=VerifiableDecisionRecord,
)
def get_verifiable_decision(
    decision_id: UUID,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> VerifiableDecisionRecord:
    return get_verifiable_decision_or_404(
        decision_id=decision_id,
        project_id=project.project_id,
        store=store,
    )


@router.get(
    "/v1/admin/projects/{project_id}/integrity/verify",
    response_model=DecisionIntegrityVerification,
    dependencies=[Depends(require_admin_access)],
)
def verify_managed_project_integrity(
    project_id: UUID,
    expected_head_hash: ExpectedHeadHashQuery = None,
    store: EvidenceStore = Depends(get_evidence_store),
) -> DecisionIntegrityVerification:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )

    return store.verify_decision_integrity(
        project_id=project_id,
        expected_head_hash=expected_head_hash,
    )

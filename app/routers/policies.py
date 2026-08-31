from fastapi import APIRouter, Depends, HTTPException

from app.dependencies import (
    get_authenticated_project,
    get_evidence_store,
)
from app.evidence_store import EvidenceStore
from app.policy_models import Policy, PolicyPage
from app.project_models import Project

router = APIRouter()


@router.get(
    "/v1/policies",
    response_model=PolicyPage,
)
def list_active_policies(
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> PolicyPage:
    policies = store.list_project_policies(
        project.project_id
    )

    return PolicyPage(
        items=policies,
        total=len(policies),
    )


@router.get(
    "/v1/policies/{policy_id}",
    response_model=Policy,
)
def get_active_policy(
    policy_id: str,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> Policy:
    policy = store.get_project_policy(
        project_id=project.project_id,
        policy_id=policy_id,
    )

    if policy is not None:
        return policy

    raise HTTPException(
        status_code=404,
        detail={
            "code": "policy_not_found",
            "message": (
                f"Policy '{policy_id}' was not found."
            ),
        },
    )

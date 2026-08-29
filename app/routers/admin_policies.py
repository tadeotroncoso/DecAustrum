from uuid import UUID

from fastapi import APIRouter, Depends

from app.dependencies import (
    get_evidence_store,
    require_admin_access,
)
from app.evidence_store import EvidenceStore
from app.policy_models import (
    Policy,
    ProjectPolicyConfiguration,
    ProjectPolicyConfigurationPage,
)
from app.services.policies import (
    configure_policy,
    disable_policy,
    get_project_policy_or_404,
)
from app.services.projects import get_project_or_404


router = APIRouter()


@router.get(
    "/v1/admin/projects/{project_id}/policies",
    response_model=ProjectPolicyConfigurationPage,
    dependencies=[Depends(require_admin_access)],
)
def list_project_policy_configurations(
    project_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyConfigurationPage:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )

    configurations = (
        store.list_project_policy_configurations(
            project_id=project_id,
        )
    )

    return ProjectPolicyConfigurationPage(
        items=configurations,
        total=len(configurations),
    )


@router.get(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}"
    ),
    response_model=ProjectPolicyConfiguration,
    dependencies=[Depends(require_admin_access)],
)
def get_project_policy_configuration(
    project_id: UUID,
    policy_id: str,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyConfiguration:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )

    return get_project_policy_or_404(
        project_id=project_id,
        policy_id=policy_id,
        store=store,
    )


@router.put(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}"
    ),
    response_model=ProjectPolicyConfiguration,
    dependencies=[Depends(require_admin_access)],
)
def configure_project_policy(
    project_id: UUID,
    policy_id: str,
    policy: Policy,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyConfiguration:
    return configure_policy(
        project_id=project_id,
        policy_id=policy_id,
        policy=policy,
        store=store,
    )


@router.delete(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}"
    ),
    response_model=ProjectPolicyConfiguration,
    dependencies=[Depends(require_admin_access)],
)
def disable_project_policy(
    project_id: UUID,
    policy_id: str,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyConfiguration:
    return disable_policy(
        project_id=project_id,
        policy_id=policy_id,
        store=store,
    )

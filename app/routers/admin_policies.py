from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query

from app.audit_models import AuditContext
from app.dependencies import (
    get_evidence_store,
    require_admin_access,
)
from app.evidence_store import EvidenceStore
from app.policy_models import (
    Policy,
    PolicyRollbackRequest,
    ProjectPolicyConfiguration,
    ProjectPolicyConfigurationPage,
    ProjectPolicyVersion,
    ProjectPolicyVersionPage,
)
from app.services.policies import (
    configure_policy,
    disable_policy,
    get_project_policy_or_404,
    get_project_policy_version_or_404,
    rollback_policy,
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


@router.get(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}/versions"
    ),
    response_model=ProjectPolicyVersionPage,
    dependencies=[Depends(require_admin_access)],
)
def list_project_policy_versions(
    project_id: UUID,
    policy_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyVersionPage:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )
    get_project_policy_or_404(
        project_id=project_id,
        policy_id=policy_id,
        store=store,
    )

    return ProjectPolicyVersionPage(
        items=store.list_project_policy_versions(
            project_id=project_id,
            policy_id=policy_id,
            limit=limit,
            offset=offset,
        ),
        total=store.count_project_policy_versions(
            project_id=project_id,
            policy_id=policy_id,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}/versions/{version}"
    ),
    response_model=ProjectPolicyVersion,
    dependencies=[Depends(require_admin_access)],
)
def get_project_policy_version(
    project_id: UUID,
    policy_id: str,
    version: int = Path(ge=1),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyVersion:
    return get_project_policy_version_or_404(
        project_id=project_id,
        policy_id=policy_id,
        version=version,
        store=store,
    )


@router.post(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}/rollback"
    ),
    response_model=ProjectPolicyConfiguration,
)
def rollback_project_policy(
    project_id: UUID,
    policy_id: str,
    request: PolicyRollbackRequest,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyConfiguration:
    return rollback_policy(
        project_id=project_id,
        policy_id=policy_id,
        source_version=request.version,
        store=store,
        audit_context=audit_context,
    )


@router.put(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}"
    ),
    response_model=ProjectPolicyConfiguration,
)
def configure_project_policy(
    project_id: UUID,
    policy_id: str,
    policy: Policy,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyConfiguration:
    return configure_policy(
        project_id=project_id,
        policy_id=policy_id,
        policy=policy,
        store=store,
        audit_context=audit_context,
    )


@router.delete(
    (
        "/v1/admin/projects/{project_id}"
        "/policies/{policy_id}"
    ),
    response_model=ProjectPolicyConfiguration,
)
def disable_project_policy(
    project_id: UUID,
    policy_id: str,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPolicyConfiguration:
    return disable_policy(
        project_id=project_id,
        policy_id=policy_id,
        store=store,
        audit_context=audit_context,
    )

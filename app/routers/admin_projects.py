from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api_keys import (
    ProjectApiKeyCreateRequest,
    ProjectApiKeyMetadata,
    ProjectApiKeyPage,
    ProjectApiKeyProvisioningResponse,
)
from app.audit_models import AuditContext
from app.dependencies import (
    get_evidence_store,
    require_admin_access,
)
from app.evidence_store import EvidenceStore
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.policy_models import Policy
from app.project_models import (
    Project,
    ProjectCreateRequest,
    ProjectPage,
    ProjectProvisioningResponse,
    ProjectStatus,
    ProjectStatusUpdateRequest,
)
from app.services.projects import (
    change_project_status,
    create_project,
    create_project_api_key,
    get_project_or_404,
    revoke_api_key,
)

router = APIRouter()


def get_policy_templates() -> list[Policy]:
    return load_policies(POLICIES_DIRECTORY)


@router.get(
    "/v1/admin/projects",
    response_model=ProjectPage,
    dependencies=[Depends(require_admin_access)],
)
def list_projects(
    status: ProjectStatus | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectPage:
    return ProjectPage(
        items=store.list_projects(
            status=status,
            limit=limit,
            offset=offset,
        ),
        total=store.count_projects(status=status),
        limit=limit,
        offset=offset,
    )


@router.post(
    "/v1/admin/projects",
    response_model=ProjectProvisioningResponse,
    status_code=201,
)
def provision_project(
    request: ProjectCreateRequest,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    policy_templates: list[Policy] = Depends(
        get_policy_templates
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectProvisioningResponse:
    return create_project(
        request=request,
        policy_templates=policy_templates,
        store=store,
        audit_context=audit_context,
    )


@router.get(
    "/v1/admin/projects/{project_id}",
    response_model=Project,
    dependencies=[Depends(require_admin_access)],
)
def get_project(
    project_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> Project:
    return get_project_or_404(
        project_id=project_id,
        store=store,
    )


@router.patch(
    "/v1/admin/projects/{project_id}",
    response_model=Project,
)
def update_project_status(
    project_id: UUID,
    request: ProjectStatusUpdateRequest,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> Project:
    return change_project_status(
        project_id=project_id,
        status=request.status,
        store=store,
        audit_context=audit_context,
    )


@router.post(
    "/v1/admin/projects/{project_id}/api-keys",
    response_model=ProjectApiKeyProvisioningResponse,
    status_code=201,
)
def provision_project_api_key(
    project_id: UUID,
    request: ProjectApiKeyCreateRequest | None = None,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectApiKeyProvisioningResponse:
    return create_project_api_key(
        project_id=project_id,
        role=(request.role if request is not None else "RUNTIME"),
        store=store,
        audit_context=audit_context,
    )


@router.get(
    "/v1/admin/projects/{project_id}/api-keys",
    response_model=ProjectApiKeyPage,
    dependencies=[Depends(require_admin_access)],
)
def list_project_api_keys(
    project_id: UUID,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectApiKeyPage:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )

    return ProjectApiKeyPage(
        items=store.list_project_api_keys(
            project_id=project_id,
            limit=limit,
            offset=offset,
        ),
        total=store.count_project_api_keys(project_id),
        limit=limit,
        offset=offset,
    )


@router.delete(
    (
        "/v1/admin/projects/{project_id}"
        "/api-keys/{api_key_id}"
    ),
    response_model=ProjectApiKeyMetadata,
)
def revoke_project_api_key(
    project_id: UUID,
    api_key_id: UUID,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectApiKeyMetadata:
    return revoke_api_key(
        project_id=project_id,
        api_key_id=api_key_id,
        store=store,
        audit_context=audit_context,
    )

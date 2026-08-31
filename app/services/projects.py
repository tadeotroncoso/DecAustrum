from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException

from app.api_keys import (
    ProjectApiKeyMetadata,
    ProjectApiKeyProvisioningResponse,
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
)
from app.audit_models import AuditContext
from app.evidence_store import EvidenceStore
from app.policy_models import Policy
from app.project_models import (
    DEFAULT_PROJECT_ID,
    Project,
    ProjectCreateRequest,
    ProjectProvisioningResponse,
    ProjectStatus,
)


def get_project_or_404(
    project_id: UUID,
    store: EvidenceStore,
) -> Project:
    project = store.get_project(project_id)

    if project is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "project_not_found",
                "message": (
                    f"Project '{project_id}' was not found."
                ),
            },
        )

    return project


def create_project(
    request: ProjectCreateRequest,
    policy_templates: list[Policy],
    store: EvidenceStore,
    audit_context: AuditContext,
) -> ProjectProvisioningResponse:
    created_at = datetime.now(timezone.utc)

    project = Project(
        project_id=uuid4(),
        name=request.name,
        status="ACTIVE",
        created_at=created_at,
        updated_at=created_at,
    )

    api_key = generate_project_api_key()

    api_key_record = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=project.project_id,
        key_prefix=get_api_key_prefix(api_key),
        key_hash=hash_api_key(api_key),
        created_at=created_at,
    )

    store.save_project_with_api_key(
        project=project,
        api_key=api_key_record,
        policies=policy_templates,
        audit_context=audit_context,
    )

    return ProjectProvisioningResponse(
        project=project,
        api_key=api_key,
    )


def create_project_api_key(
    project_id: UUID,
    store: EvidenceStore,
    audit_context: AuditContext,
) -> ProjectApiKeyProvisioningResponse:
    project = get_project_or_404(
        project_id=project_id,
        store=store,
    )

    if project.status != "ACTIVE":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "project_disabled",
                "message": (
                    f"Project '{project_id}' is disabled."
                ),
            },
        )

    created_at = datetime.now(timezone.utc)
    api_key = generate_project_api_key()

    record = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=project_id,
        key_prefix=get_api_key_prefix(api_key),
        key_hash=hash_api_key(api_key),
        created_at=created_at,
    )

    store.save_project_api_key(
        record,
        audit_context=audit_context,
    )

    metadata = ProjectApiKeyMetadata(
        api_key_id=record.api_key_id,
        project_id=record.project_id,
        key_prefix=record.key_prefix,
        created_at=record.created_at,
        revoked_at=record.revoked_at,
    )

    return ProjectApiKeyProvisioningResponse(
        key=metadata,
        api_key=api_key,
    )


def change_project_status(
    project_id: UUID,
    status: ProjectStatus,
    store: EvidenceStore,
    audit_context: AuditContext,
) -> Project:
    if (
        project_id == DEFAULT_PROJECT_ID
        and status == "DISABLED"
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "default_project_protected",
                "message": (
                    "The default project cannot be disabled."
                ),
            },
        )

    project = store.update_project_status(
        project_id=project_id,
        status=status,
        updated_at=datetime.now(timezone.utc),
        audit_context=audit_context,
    )

    if project is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "project_not_found",
                "message": (
                    f"Project '{project_id}' was not found."
                ),
            },
        )

    return project


def revoke_api_key(
    project_id: UUID,
    api_key_id: UUID,
    store: EvidenceStore,
    audit_context: AuditContext,
) -> ProjectApiKeyMetadata:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )

    revoked_key = store.revoke_project_api_key(
        project_id=project_id,
        api_key_id=api_key_id,
        revoked_at=datetime.now(timezone.utc),
        audit_context=audit_context,
    )

    if revoked_key is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "api_key_not_found",
                "message": (
                    f"API key '{api_key_id}' was not found "
                    f"for project '{project_id}'."
                ),
            },
        )

    return revoked_key

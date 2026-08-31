from datetime import datetime, timezone
from uuid import uuid4

from app.api_keys import (
    ProjectApiKeyRecord,
    get_api_key_prefix,
    hash_api_key,
)
from app.audit import SYSTEM_BOOTSTRAP_AUDIT_CONTEXT
from app.evidence_store import EvidenceStore
from app.project_models import (
    DEFAULT_PROJECT_ID,
    DEFAULT_PROJECT_NAME,
    Project,
)


def bootstrap_default_project(
    store: EvidenceStore,
    api_key: str,
    *,
    created_at: datetime | None = None,
) -> Project:
    key_hash = hash_api_key(api_key)

    authenticated_project = (
        store.get_active_project_by_api_key_hash(
            key_hash
        )
    )

    if authenticated_project is not None:
        return authenticated_project

    timestamp = created_at or datetime.now(
        timezone.utc
    )

    project = store.get_project(DEFAULT_PROJECT_ID)

    api_key_record = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=DEFAULT_PROJECT_ID,
        key_prefix=get_api_key_prefix(api_key),
        key_hash=key_hash,
        created_at=timestamp,
    )

    if project is None:
        project = Project(
            project_id=DEFAULT_PROJECT_ID,
            name=DEFAULT_PROJECT_NAME,
            status="ACTIVE",
            created_at=timestamp,
            updated_at=timestamp,
        )

        store.save_project_with_api_key(
            project=project,
            api_key=api_key_record,
            audit_context=SYSTEM_BOOTSTRAP_AUDIT_CONTEXT,
        )

        return project

    if project.status != "ACTIVE":
        raise RuntimeError(
            "Default project is disabled."
        )

    store.save_project_api_key(
        api_key_record,
        audit_context=SYSTEM_BOOTSTRAP_AUDIT_CONTEXT,
    )

    return project

from pathlib import Path
from typing import Annotated

from fastapi import Depends

from app.evidence_store import EvidenceStore
from app.project_models import Project
from app.security import (
    admin_api_key_header,
    api_key_header,
    authenticate_admin,
    authenticate_project,
    get_configured_admin_api_key,
)


DATABASE_PATH = Path("data/regtrace.db")
evidence_store = EvidenceStore(DATABASE_PATH)


def get_evidence_store() -> EvidenceStore:
    return evidence_store


def get_authenticated_project(
    provided_api_key: Annotated[
        str | None,
        Depends(api_key_header),
    ],
    store: EvidenceStore = Depends(get_evidence_store),
) -> Project:
    return authenticate_project(
        provided_api_key=provided_api_key,
        store=store,
    )


def require_admin_access(
    provided_api_key: Annotated[
        str | None,
        Depends(admin_api_key_header),
    ],
) -> None:
    authenticate_admin(
        provided_api_key=provided_api_key,
        configured_api_key=(
            get_configured_admin_api_key()
        ),
    )

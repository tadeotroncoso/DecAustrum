import os
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader

from app.api_keys import hash_api_key
from app.evidence_store import EvidenceStore
from app.project_models import Project


API_KEY_ENVIRONMENT_VARIABLE = "REGTRACE_API_KEY"

api_key_header = APIKeyHeader(
    name="X-API-Key",
    scheme_name="RegTraceApiKey",
    description="API key required to access RegTrace v1 endpoints.",
    auto_error=False,
)


def get_configured_api_key() -> str:
    api_key = os.getenv(API_KEY_ENVIRONMENT_VARIABLE)

    if not api_key:
        raise RuntimeError(
            f"{API_KEY_ENVIRONMENT_VARIABLE} must be configured."
        )

    return api_key


def require_api_key(
    provided_api_key: Annotated[
        str | None,
        Depends(api_key_header),
    ],
) -> None:
    configured_api_key = get_configured_api_key()

    if (
        provided_api_key is None
        or not secrets.compare_digest(
            provided_api_key,
            configured_api_key,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_api_key",
                "message": "A valid API key is required.",
            },
        )

def authenticate_project(
    provided_api_key: str | None,
    store: EvidenceStore,
) -> Project:
    if not provided_api_key:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_api_key",
                "message": "A valid API key is required.",
            },
        )

    key_hash = hash_api_key(provided_api_key)

    project = (
        store.get_active_project_by_api_key_hash(
            key_hash
        )
    )

    if project is None:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_api_key",
                "message": "A valid API key is required.",
            },
        )

    return project
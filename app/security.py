import os
import secrets

from fastapi import HTTPException
from fastapi.security import APIKeyHeader

from app.api_keys import hash_api_key
from app.evidence_store import EvidenceStore
from app.project_models import Project


API_KEY_ENVIRONMENT_VARIABLE = "REGTRACE_API_KEY"
ADMIN_API_KEY_ENVIRONMENT_VARIABLE = (
    "REGTRACE_ADMIN_API_KEY"
)
WEBHOOK_MASTER_SECRET_ENVIRONMENT_VARIABLE = (
    "REGTRACE_WEBHOOK_MASTER_SECRET"
)
EXECUTION_GRANT_SECRET_ENVIRONMENT_VARIABLE = (
    "REGTRACE_EXECUTION_GRANT_SECRET"
)

api_key_header = APIKeyHeader(
    name="X-API-Key",
    scheme_name="RegTraceApiKey",
    description="API key required to access RegTrace v1 endpoints.",
    auto_error=False,
)

admin_api_key_header = APIKeyHeader(
    name="X-Admin-API-Key",
    scheme_name="RegTraceAdminApiKey",
    description=(
        "Administrative API key required to provision "
        "RegTrace projects."
    ),
    auto_error=False,
)


def get_configured_api_key() -> str:
    api_key = os.getenv(API_KEY_ENVIRONMENT_VARIABLE)

    if not api_key:
        raise RuntimeError(
            f"{API_KEY_ENVIRONMENT_VARIABLE} must be configured."
        )

    return api_key


def get_configured_admin_api_key() -> str:
    api_key = os.getenv(
        ADMIN_API_KEY_ENVIRONMENT_VARIABLE
    )

    if not api_key:
        raise RuntimeError(
            f"{ADMIN_API_KEY_ENVIRONMENT_VARIABLE} "
            "must be configured."
        )

    return api_key


def get_configured_webhook_master_secret() -> str:
    secret = os.getenv(
        WEBHOOK_MASTER_SECRET_ENVIRONMENT_VARIABLE
    )

    if not secret:
        raise RuntimeError(
            f"{WEBHOOK_MASTER_SECRET_ENVIRONMENT_VARIABLE} "
            "must be configured to provision or deliver webhooks."
        )

    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError(
            f"{WEBHOOK_MASTER_SECRET_ENVIRONMENT_VARIABLE} "
            "must contain at least 32 bytes."
        )

    return secret


def get_configured_execution_grant_secret() -> str:
    secret = os.getenv(
        EXECUTION_GRANT_SECRET_ENVIRONMENT_VARIABLE
    )

    if not secret:
        raise RuntimeError(
            f"{EXECUTION_GRANT_SECRET_ENVIRONMENT_VARIABLE} "
            "must be configured to issue or consume execution grants."
        )

    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError(
            f"{EXECUTION_GRANT_SECRET_ENVIRONMENT_VARIABLE} "
            "must contain at least 32 bytes."
        )

    return secret


def authenticate_admin(
    provided_api_key: str | None,
    configured_api_key: str,
) -> None:
    if (
        not provided_api_key
        or not secrets.compare_digest(
            provided_api_key,
            configured_api_key,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "invalid_admin_api_key",
                "message": (
                    "A valid admin API key is required."
                ),
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

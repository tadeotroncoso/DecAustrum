import os
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import APIKeyHeader


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
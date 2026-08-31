"""Shared HTTP and input-validation helpers for SDK clients."""

import json
from copy import deepcopy
from typing import Any, Callable, Mapping, TypeVar
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx

from decaustrum._version import __version__
from decaustrum.errors import (
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    DecAustrumAPIError,
    DecAustrumProtocolError,
    ServerError,
    ValidationError,
)


SDK_VERSION = __version__
DEFAULT_BASE_URL = "http://localhost:8000"
DEFAULT_TIMEOUT = 10.0
ModelT = TypeVar("ModelT")


def normalize_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("base_url must be a non-empty URL")

    normalized = base_url.strip().rstrip("/")
    parsed = urlsplit(normalized)

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("base_url must be an HTTP(S) origin or URL prefix")

    return normalized


def normalize_api_key(api_key: str) -> str:
    if not isinstance(api_key, str) or not api_key:
        raise ValueError("api_key must be a non-empty string")
    return api_key


def normalize_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def normalize_optional_reason(reason: str | None) -> str | None:
    if reason is None:
        return None
    normalized = normalize_identifier(reason, "reason")
    if len(normalized) > 500:
        raise ValueError("reason must contain at most 500 characters")
    return normalized


def normalize_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = normalize_identifier(value, "idempotency_key")
    if len(normalized) > 255:
        raise ValueError(
            "idempotency_key must contain at most 255 characters"
        )
    return normalized


def normalize_context(context: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(context, Mapping):
        raise TypeError("context must be a mapping")

    normalized = deepcopy(dict(context))

    if not all(isinstance(key, str) for key in normalized):
        raise ValueError("context keys must be strings")

    try:
        json.dumps(normalized, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("context must contain valid JSON values") from exc

    return normalized


def normalize_uuid(value: UUID | str, name: str) -> UUID:
    try:
        return value if isinstance(value, UUID) else UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"{name} must be a UUID") from exc


def normalize_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("timeout must be a number")
    if value <= 0:
        raise ValueError("timeout must be greater than zero")
    return float(value)


def normalize_page(limit: int, offset: int) -> tuple[int, int]:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise TypeError("offset must be an integer")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if offset < 0:
        raise ValueError("offset must be greater than or equal to zero")
    return limit, offset


def build_url(base_url: str, path: str) -> str:
    return f"{base_url}/{path.lstrip('/')}"


def build_headers(
    api_key: str,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": f"decaustrum-python/{SDK_VERSION}",
        "X-API-Key": api_key,
        "X-Request-ID": str(uuid4()),
    }
    headers.update(extra or {})
    return headers


def _error_payload(response: httpx.Response) -> tuple[str, str, Any]:
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        payload = None

    detail = payload.get("detail") if isinstance(payload, Mapping) else None

    if isinstance(detail, Mapping):
        raw_code = detail.get("code")
        raw_message = detail.get("message")
        code = (
            raw_code
            if isinstance(raw_code, str) and raw_code
            else "api_error"
        )
        message = (
            raw_message
            if isinstance(raw_message, str) and raw_message
            else "DecAustrum rejected the request."
        )
        return code, message, deepcopy(dict(detail))

    if isinstance(detail, list):
        return (
            "validation_error",
            "DecAustrum rejected the request as invalid.",
            deepcopy(detail),
        )

    return (
        "http_error",
        response.reason_phrase or "DecAustrum rejected the request.",
        deepcopy(detail),
    )


def raise_for_status(response: httpx.Response) -> None:
    if response.status_code < 400:
        return

    code, message, details = _error_payload(response)
    error_type: type[DecAustrumAPIError]

    if response.status_code in {401, 403}:
        error_type = AuthenticationError
    elif response.status_code == 404:
        error_type = NotFoundError
    elif response.status_code == 409:
        error_type = ConflictError
    elif response.status_code == 422:
        error_type = ValidationError
    elif response.status_code == 429:
        error_type = RateLimitError
    elif response.status_code >= 500:
        error_type = ServerError
    else:
        error_type = DecAustrumAPIError

    raise error_type(
        status_code=response.status_code,
        code=code,
        message=message,
        request_id=response.headers.get("X-Request-ID"),
        details=details,
        retry_after=response.headers.get("Retry-After"),
    )


def parse_response(
    response: httpx.Response,
    parser: Callable[[Mapping[str, Any]], ModelT],
) -> ModelT:
    raise_for_status(response)

    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise DecAustrumProtocolError(
            "DecAustrum returned a non-JSON success response."
        ) from exc

    if not isinstance(payload, Mapping):
        raise DecAustrumProtocolError(
            "DecAustrum returned a success response that is not an object."
        )

    try:
        return parser(payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise DecAustrumProtocolError(
            "DecAustrum returned a response that does not match "
            "the SDK contract."
        ) from exc


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_TIMEOUT",
    "SDK_VERSION",
    "build_headers",
    "build_url",
    "normalize_api_key",
    "normalize_base_url",
    "normalize_context",
    "normalize_identifier",
    "normalize_idempotency_key",
    "normalize_optional_reason",
    "normalize_page",
    "normalize_timeout",
    "normalize_uuid",
    "parse_response",
]

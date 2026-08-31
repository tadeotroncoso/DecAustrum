import base64
import hashlib
import hmac
import json

from pydantic import ValidationError

from app.exceptions import InvalidExecutionGrantError
from app.execution_models import (
    ExecutionGrantPayload,
    ExecutionGrantRecord,
)

EXECUTION_GRANT_PREFIX = "rgt_exec_v1"


def _validate_secret(secret: str) -> bytes:
    encoded = secret.encode("utf-8")

    if len(encoded) < 32:
        raise ValueError(
            "Execution grant secret must contain at least 32 bytes."
        )

    return encoded


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    if not value or "=" in value:
        raise InvalidExecutionGrantError()

    padding = "=" * (-len(value) % 4)

    try:
        decoded = base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise InvalidExecutionGrantError() from exc

    if not hmac.compare_digest(
        _base64url_encode(decoded),
        value,
    ):
        raise InvalidExecutionGrantError()

    return decoded


def _payload_segment(payload: ExecutionGrantPayload) -> str:
    canonical = json.dumps(
        payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return _base64url_encode(canonical)


def build_execution_grant_token(
    payload: ExecutionGrantPayload | ExecutionGrantRecord,
    secret: str,
) -> str:
    secret_bytes = _validate_secret(secret)
    normalized_payload = ExecutionGrantPayload(
        version=payload.version,
        grant_id=payload.grant_id,
        decision_id=payload.decision_id,
        project_id=payload.project_id,
        request_fingerprint=payload.request_fingerprint,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
    )
    segment = _payload_segment(normalized_payload)
    signing_input = (
        f"{EXECUTION_GRANT_PREFIX}.{segment}"
    ).encode("ascii")
    signature = hmac.new(
        secret_bytes,
        signing_input,
        hashlib.sha256,
    ).digest()

    return (
        f"{EXECUTION_GRANT_PREFIX}.{segment}."
        f"{_base64url_encode(signature)}"
    )


def parse_execution_grant_token(
    token: str,
    secret: str,
) -> ExecutionGrantPayload:
    secret_bytes = _validate_secret(secret)
    parts = token.split(".")

    if len(parts) != 3 or parts[0] != EXECUTION_GRANT_PREFIX:
        raise InvalidExecutionGrantError()

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected_signature = hmac.new(
        secret_bytes,
        signing_input,
        hashlib.sha256,
    ).digest()
    actual_signature = _base64url_decode(parts[2])

    if not hmac.compare_digest(
        expected_signature,
        actual_signature,
    ):
        raise InvalidExecutionGrantError()

    try:
        raw_payload = json.loads(
            _base64url_decode(parts[1]).decode("utf-8")
        )
        payload = ExecutionGrantPayload.model_validate(raw_payload)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        TypeError,
    ) as exc:
        raise InvalidExecutionGrantError() from exc

    if _payload_segment(payload) != parts[1]:
        raise InvalidExecutionGrantError()

    return payload


def hash_execution_grant_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

import hashlib
import re
import secrets
import threading
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.project_models import Project

API_KEY_MARKER = "dak_"
API_KEY_SCRYPT_N = 2**14
API_KEY_SCRYPT_R = 8
API_KEY_SCRYPT_P = 5
# Bound memory used by concurrent KDFs (about 16 MiB each). These functions run
# in synchronous FastAPI dependencies/services, not on the async event loop.
_API_KEY_KDF_SLOTS = threading.BoundedSemaphore(2)
API_KEY_PATTERN = re.compile(r"dak_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}")
API_KEY_HASH_PATTERN = (
    r"scrypt\$16384\$8\$5\$[0-9a-f]{32}\$[0-9a-f]{64}"
)
ProjectApiKeyRole = Literal["RUNTIME", "REVIEWER"]

ApiKeyHash = Annotated[
    str,
    StringConstraints(
        pattern=rf"^{API_KEY_HASH_PATTERN}$",
    ),
]

ApiKeyPrefix = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=48,
    ),
]


class ProjectApiKeyRecord(BaseModel):
    api_key_id: UUID
    project_id: UUID
    key_prefix: ApiKeyPrefix
    key_hash: ApiKeyHash
    role: ProjectApiKeyRole = "RUNTIME"
    created_at: datetime
    revoked_at: datetime | None = None


class ProjectApiKeyMetadata(BaseModel):
    api_key_id: UUID
    project_id: UUID
    key_prefix: ApiKeyPrefix
    role: ProjectApiKeyRole = "RUNTIME"
    created_at: datetime
    revoked_at: datetime | None = None


class ProjectApiKeyPage(BaseModel):
    items: list[ProjectApiKeyMetadata]
    total: int
    limit: int
    offset: int


class ProjectApiKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: ProjectApiKeyRole = "RUNTIME"


class ProjectApiKeyPrincipal(BaseModel):
    api_key_id: UUID
    role: ProjectApiKeyRole
    project: Project


class ProjectApiKeyProvisioningResponse(BaseModel):
    key: ProjectApiKeyMetadata
    api_key: str


def generate_project_api_key() -> str:
    """Issue a public lookup selector and an independent 256-bit secret."""
    return f"{API_KEY_MARKER}{secrets.token_hex(8)}.{secrets.token_urlsafe(32)}"


def _derive_api_key(api_key: str, salt: bytes) -> bytes:
    with _API_KEY_KDF_SLOTS:
        return hashlib.scrypt(
            api_key.encode("utf-8"), salt=salt, n=API_KEY_SCRYPT_N,
            r=API_KEY_SCRYPT_R, p=API_KEY_SCRYPT_P, dklen=32,
            maxmem=32 * 1024 * 1024,
        )


def hash_api_key(api_key: str) -> str:
    """Create a salted verifier, never a lookup digest or plaintext credential."""
    if not api_key:
        raise ValueError("API key cannot be empty.")

    salt = secrets.token_bytes(16)
    derived = _derive_api_key(api_key, salt)
    return (
        f"scrypt${API_KEY_SCRYPT_N}${API_KEY_SCRYPT_R}${API_KEY_SCRYPT_P}"
        f"${salt.hex()}${derived.hex()}"
    )


def verify_api_key(api_key: str, verifier: str) -> bool:
    """Reject retired, malformed, or unsupported verifiers without a fallback."""
    if not api_key or re.fullmatch(API_KEY_HASH_PATTERN, verifier) is None:
        return False
    _, _, _, _, salt, expected = verifier.split("$")
    derived = _derive_api_key(api_key, bytes.fromhex(salt))
    return secrets.compare_digest(derived, bytes.fromhex(expected))


def get_api_key_prefix(api_key: str) -> str:
    """Return only the public selector; it contains no part of the secret."""
    if API_KEY_PATTERN.fullmatch(api_key) is None:
        raise ValueError("API key must use the current selector.secret format.")
    return api_key.split(".", 1)[0]

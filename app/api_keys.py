import hashlib
import secrets
from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, StringConstraints


API_KEY_MARKER = "rtk_"

ApiKeyHash = Annotated[
    str,
    StringConstraints(
        pattern=r"^[0-9a-f]{64}$",
    ),
]

ApiKeyPrefix = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=20,
    ),
]


class ProjectApiKeyRecord(BaseModel):
    api_key_id: UUID
    project_id: UUID
    key_prefix: ApiKeyPrefix
    key_hash: ApiKeyHash
    created_at: datetime
    revoked_at: datetime | None = None


class ProjectApiKeyMetadata(BaseModel):
    api_key_id: UUID
    project_id: UUID
    key_prefix: ApiKeyPrefix
    created_at: datetime
    revoked_at: datetime | None = None


class ProjectApiKeyPage(BaseModel):
    items: list[ProjectApiKeyMetadata]
    total: int
    limit: int
    offset: int


class ProjectApiKeyProvisioningResponse(BaseModel):
    key: ProjectApiKeyMetadata
    api_key: str


def generate_project_api_key() -> str:
    return (
        API_KEY_MARKER
        + secrets.token_urlsafe(32)
    )


def hash_api_key(api_key: str) -> str:
    if not api_key:
        raise ValueError("API key cannot be empty.")

    return hashlib.sha256(
        api_key.encode("utf-8")
    ).hexdigest()


def get_api_key_prefix(api_key: str) -> str:
    if not api_key:
        raise ValueError("API key cannot be empty.")

    return api_key[:12]

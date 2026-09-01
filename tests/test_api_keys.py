from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api_keys import (
    ProjectApiKeyCreateRequest,
    ProjectApiKeyMetadata,
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
)


def test_generate_project_api_key_is_unique():
    first_key = generate_project_api_key()
    second_key = generate_project_api_key()

    assert first_key.startswith("dak_")
    assert second_key.startswith("dak_")
    assert first_key != second_key
    assert len(first_key) > 40


def test_hash_api_key_is_deterministic():
    api_key = "dak_example-secret"

    first_hash = hash_api_key(api_key)
    second_hash = hash_api_key(api_key)

    assert first_hash == second_hash
    assert len(first_hash) == 64
    assert api_key not in first_hash
    assert first_hash != hash_api_key(
        "dak_different-secret"
    )


def test_project_api_key_record_accepts_hash():
    secret = generate_project_api_key()

    record = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=uuid4(),
        key_prefix=get_api_key_prefix(secret),
        key_hash=hash_api_key(secret),
        created_at=datetime.now(timezone.utc),
    )

    assert record.key_prefix == secret[:12]
    assert record.role == "RUNTIME"
    assert record.revoked_at is None
    assert not hasattr(record, "secret")


def test_project_api_key_record_rejects_invalid_hash():
    with pytest.raises(ValidationError):
        ProjectApiKeyRecord(
            api_key_id=uuid4(),
            project_id=uuid4(),
            key_prefix="dak_example1",
            key_hash="not-a-valid-sha256-hash",
            created_at=datetime.now(timezone.utc),
        )


def test_public_api_key_metadata_excludes_secrets():
    metadata = ProjectApiKeyMetadata(
        api_key_id=uuid4(),
        project_id=uuid4(),
        key_prefix="dak_example1",
        created_at=datetime.now(timezone.utc),
    )

    public_data = metadata.model_dump()

    assert public_data["role"] == "RUNTIME"
    assert "api_key" not in public_data
    assert "key_hash" not in public_data


def test_api_key_create_request_accepts_known_roles():
    assert ProjectApiKeyCreateRequest().role == "RUNTIME"
    assert ProjectApiKeyCreateRequest(role="REVIEWER").role == (
        "REVIEWER"
    )


def test_api_key_create_request_rejects_unknown_role():
    with pytest.raises(ValidationError):
        ProjectApiKeyCreateRequest(role="ADMIN")

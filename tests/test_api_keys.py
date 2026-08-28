from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.api_keys import (
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
)


def test_generate_project_api_key_is_unique():
    first_key = generate_project_api_key()
    second_key = generate_project_api_key()

    assert first_key.startswith("rtk_")
    assert second_key.startswith("rtk_")
    assert first_key != second_key
    assert len(first_key) > 40


def test_hash_api_key_is_deterministic():
    api_key = "rtk_example-secret"

    first_hash = hash_api_key(api_key)
    second_hash = hash_api_key(api_key)

    assert first_hash == second_hash
    assert len(first_hash) == 64
    assert api_key not in first_hash
    assert first_hash != hash_api_key(
        "rtk_different-secret"
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
    assert record.revoked_at is None
    assert not hasattr(record, "secret")


def test_project_api_key_record_rejects_invalid_hash():
    with pytest.raises(ValidationError):
        ProjectApiKeyRecord(
            api_key_id=uuid4(),
            project_id=uuid4(),
            key_prefix="rtk_example1",
            key_hash="not-a-valid-sha256-hash",
            created_at=datetime.now(timezone.utc),
        )
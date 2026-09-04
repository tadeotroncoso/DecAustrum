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
    verify_api_key,
)


def test_generate_project_api_key_is_unique():
    first_key = generate_project_api_key()
    second_key = generate_project_api_key()

    assert first_key.startswith("dak_")
    assert second_key.startswith("dak_")
    assert first_key != second_key
    assert len(first_key) > 40


def test_hash_api_key_uses_independent_salts():
    api_key = "dak_example-secret"

    first_hash = hash_api_key(api_key)
    second_hash = hash_api_key(api_key)

    assert first_hash != second_hash
    assert first_hash.startswith("scrypt$16384$8$5$")
    assert first_hash.split("$")[4] != second_hash.split("$")[4]
    assert verify_api_key(api_key, first_hash)
    assert verify_api_key(api_key, second_hash)
    assert not verify_api_key("wrong", first_hash)
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

    assert record.key_prefix == secret.split(".")[0]
    assert secret.split(".")[1] not in record.key_prefix
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


@pytest.mark.parametrize("verifier", [
    "", "a" * 64, "retired$identifier",
    "scrypt$1$8$5$" + "a" * 32 + "$" + "a" * 64,
    "scrypt$999999999$8$5$" + "a" * 32 + "$" + "a" * 64,
    "scrypt$16384$8$5$not-hex$" + "a" * 64,
    "scrypt$16384$8$5$" + "a" * 32 + "$" + "a" * 64 + "\n",
])
def test_invalid_verifiers_fail_closed_without_computing(monkeypatch, verifier):
    def unexpected_kdf(*args, **kwargs):
        pytest.fail("Malformed verifier must not trigger a KDF")

    monkeypatch.setattr("app.api_keys.hashlib.scrypt", unexpected_kdf)
    assert not verify_api_key("synthetic", verifier)


def test_kdf_matches_reference_parameters(monkeypatch):
    import hashlib

    salt = bytes(range(16))
    monkeypatch.setattr("app.api_keys.secrets.token_bytes", lambda count: salt)
    secret = "synthetic-\u00f1-\u0000-test"
    expected = hashlib.scrypt(
        secret.encode(), salt=salt, n=2**14, r=8, p=5, dklen=32,
        maxmem=32 * 1024 * 1024,
    )
    verifier = hash_api_key(secret)
    assert verifier == f"scrypt$16384$8$5${salt.hex()}${expected.hex()}"
    assert verify_api_key(secret, verifier)
    assert not verify_api_key("", verifier)
    with pytest.raises(ValueError, match="cannot be empty"):
        hash_api_key("")


def test_kdf_concurrency_is_bounded_and_slots_are_released(monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = 0
    maximum = 0

    def fake_scrypt(*args, **kwargs):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(maximum, active)
            if active == 2:
                entered.set()
        try:
            assert release.wait(5)
            return bytes(32)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr("app.api_keys.hashlib.scrypt", fake_scrypt)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(hash_api_key, "synthetic") for _ in range(4)]
        try:
            assert entered.wait(5)
            assert maximum == 2
        finally:
            release.set()
        for future in futures:
            assert future.result().startswith("scrypt$")
    assert maximum == 2


def test_configured_legacy_key_fails_without_leaking_value(monkeypatch):
    from app.security import get_configured_api_key

    legacy = "legacy-" + "synthetic-test-value"
    monkeypatch.setenv("DECAUSTRUM_API_KEY", legacy)
    with pytest.raises(RuntimeError, match="newly generated") as error:
        get_configured_api_key()
    assert legacy not in str(error.value)

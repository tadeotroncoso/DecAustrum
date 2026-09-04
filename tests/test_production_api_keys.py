"""Production provisioning tests use only isolated stores and synthetic secrets."""

import base64
import logging
import secrets
from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.api_keys import generate_project_api_key, get_api_key_prefix
from app.bootstrap import bootstrap_default_project
from app.dependencies import get_evidence_store
from app.evidence_store import EvidenceStore
from app.project_models import DEFAULT_PROJECT_ID
from app.runtime_config import RuntimeConfigurationError, RuntimeSettings


@pytest.fixture
def production(monkeypatch, tmp_path):
    # Never use the developer's environment credentials or application database.
    monkeypatch.delenv("DECAUSTRUM_API_KEY", raising=False)
    monkeypatch.delenv("DECAUSTRUM_WEBHOOK_MASTER_SECRET", raising=False)
    admin_key = secrets.token_urlsafe(32)
    monkeypatch.setenv("DECAUSTRUM_ADMIN_API_KEY", admin_key)
    monkeypatch.setenv("DECAUSTRUM_EXECUTION_GRANT_SECRET", secrets.token_urlsafe(32))
    store = EvidenceStore(tmp_path / "isolated.db")
    monkeypatch.setattr(main_module, "evidence_store", store)
    application = main_module.create_app(
        RuntimeSettings.from_environment(
            {
                "DECAUSTRUM_ENVIRONMENT": "production",
                "DECAUSTRUM_TRUSTED_HOSTS": "testserver",
            }
        )
    )
    application.dependency_overrides[get_evidence_store] = lambda: store
    return application, store, {"X-Admin-API-Key": admin_key}


def test_production_starts_without_enrolling_a_configured_key(production):
    application, store, _ = production
    with TestClient(application, base_url="https://testserver") as client:
        assert client.get("/health/ready").status_code == 200
        assert store.count_projects() == 0
        assert store.get_project(DEFAULT_PROJECT_ID) is None
        assert client.get("/v1/policies").status_code == 401


@pytest.mark.parametrize(
    "missing_secret",
    ["DECAUSTRUM_ADMIN_API_KEY", "DECAUSTRUM_EXECUTION_GRANT_SECRET"],
)
def test_production_still_requires_server_secrets(
    production, monkeypatch, missing_secret
):
    application, store, _ = production
    monkeypatch.delenv(missing_secret)
    initialize = Mock(wraps=store.initialize)
    monkeypatch.setattr(store, "initialize", initialize)
    with pytest.raises(RuntimeConfigurationError, match="must be configured"):
        with TestClient(application, base_url="https://testserver"):
            pass
    initialize.assert_not_called()


@pytest.mark.parametrize("configured_key", ["", "p" * 32, "dak_" + "a" * 43])
def test_production_rejects_env_enrollment_before_storage(
    production, monkeypatch, configured_key, caplog
):
    application, store, _ = production
    monkeypatch.setenv("DECAUSTRUM_API_KEY", configured_key)
    initialize = Mock(wraps=store.initialize)
    monkeypatch.setattr(store, "initialize", initialize)
    with pytest.raises(RuntimeConfigurationError, match="must be unset") as error:
        with TestClient(application, base_url="https://testserver"):
            pass
    initialize.assert_not_called()
    if configured_key:
        assert configured_key not in str(error.value)
        assert configured_key not in caplog.text


def test_production_only_provisions_random_keys_through_admin_api(production, caplog):
    application, store, admin_headers = production
    with (
        caplog.at_level(logging.INFO),
        TestClient(application, base_url="https://testserver") as client,
    ):
        denied = client.post("/v1/admin/projects", json={"name": "Isolated"})
        assert denied.status_code == 401
        assert store.count_projects() == 0
        response = client.post(
            "/v1/admin/projects", headers=admin_headers, json={"name": "Isolated"}
        )
        assert response.status_code == 201
        data = response.json()
        project_id = data["project"]["project_id"]
        first_key = data["api_key"]
        assert first_key.startswith("dak_")
        assert len(base64.urlsafe_b64decode(first_key.split(".")[1] + "=")) == 32
        principal = store.get_active_api_key_principal(first_key)
        assert principal is not None
        assert principal.project.project_id == UUID(project_id)
        assert (
            client.get("/v1/policies", headers={"X-API-Key": first_key}).status_code
            == 200
        )
        second = client.post(
            f"/v1/admin/projects/{project_id}/api-keys",
            headers=admin_headers,
            json={"role": "REVIEWER"},
        )
        assert second.status_code == 201
        second_key = second.json()["api_key"]
        assert second_key != first_key
        assert len(base64.urlsafe_b64decode(second_key.split(".")[1] + "=")) == 32
        metadata = client.get(
            f"/v1/admin/projects/{project_id}/api-keys", headers=admin_headers
        )
        assert metadata.status_code == 200
        assert first_key not in metadata.text
        assert second_key not in metadata.text
        assert first_key not in caplog.text
        assert second_key not in caplog.text
        with store.database.connect() as connection:
            stored_verifier = connection.execute(
                "SELECT key_hash FROM project_api_keys WHERE key_prefix = ?",
                (get_api_key_prefix(first_key),),
            ).fetchone()[0]
        assert stored_verifier not in metadata.text
        assert stored_verifier not in caplog.text


def test_production_refuses_caller_selected_credentials(production):
    application, store, admin_headers = production
    with TestClient(application, base_url="https://testserver") as client:
        injected = {"name": "Isolated", "api_key": "predictable" * 4}
        response = client.post(
            "/v1/admin/projects", headers=admin_headers, json=injected
        )
        assert response.status_code == 422
        assert "predictable" * 4 not in response.text
        assert store.count_projects() == 0
        created = client.post(
            "/v1/admin/projects", headers=admin_headers, json={"name": "Isolated"}
        )
        assert created.status_code == 201
        project_id = created.json()["project"]["project_id"]
        response = client.post(
            f"/v1/admin/projects/{project_id}/api-keys",
            headers=admin_headers,
            json={"role": "RUNTIME", "api_key": "predictable" * 4},
        )
        assert response.status_code == 422
        assert "predictable" * 4 not in response.text
        assert store.count_project_api_keys(UUID(project_id)) == 1


@pytest.mark.parametrize("revoked", [False, True])
def test_production_preserves_current_keys_without_reenrollment(production, revoked):
    application, store, _ = production
    store.initialize()
    # A key already enrolled with the current salted verifier.
    legacy_key = generate_project_api_key()
    project = bootstrap_default_project(store, legacy_key)
    principal = store.get_active_api_key_principal(legacy_key)
    assert principal is not None
    if revoked:
        store.revoke_project_api_key(
            project.project_id, principal.api_key_id, datetime.now(timezone.utc)
        )
    for _ in range(2):
        with TestClient(application, base_url="https://testserver") as client:
            assert store.count_projects() == 1
            assert store.count_project_api_keys(project.project_id) == 1
            response = client.get("/v1/policies", headers={"X-API-Key": legacy_key})
            assert response.status_code == (401 if revoked else 200)


def test_project_key_generator_requests_32_random_bytes(monkeypatch):
    token = Mock(return_value="synthetic-generator-result")
    monkeypatch.setattr("app.api_keys.secrets.token_urlsafe", token)
    selector = Mock(return_value="0123456789abcdef")
    monkeypatch.setattr("app.api_keys.secrets.token_hex", selector)
    assert generate_project_api_key() == (
        "dak_0123456789abcdef.synthetic-generator-result"
    )
    token.assert_called_once_with(32)
    selector.assert_called_once_with(8)


def test_production_can_rotate_current_key_without_server_configuration(production):
    application, store, admin_headers = production
    store.initialize()
    legacy_key = generate_project_api_key()
    project = bootstrap_default_project(store, legacy_key)
    old = store.get_active_api_key_principal(legacy_key)
    assert old is not None
    with TestClient(application, base_url="https://testserver") as client:
        issued = client.post(
            f"/v1/admin/projects/{project.project_id}/api-keys",
            headers=admin_headers,
            json={"role": "RUNTIME"},
        )
        assert issued.status_code == 201
        new_key = issued.json()["api_key"]
        for credential in (legacy_key, new_key):
            assert (
                client.get(
                    "/v1/policies", headers={"X-API-Key": credential}
                ).status_code
                == 200
            )
        revoked = client.delete(
            f"/v1/admin/projects/{project.project_id}/api-keys/{old.api_key_id}",
            headers=admin_headers,
        )
        assert revoked.status_code == 200
    with TestClient(application, base_url="https://testserver") as client:
        assert (
            client.get("/v1/policies", headers={"X-API-Key": legacy_key}).status_code
            == 401
        )
        assert (
            client.get("/v1/policies", headers={"X-API-Key": new_key}).status_code
            == 200
        )
        assert store.count_project_api_keys(project.project_id) == 2


def test_local_development_keeps_default_project_bootstrap(production, monkeypatch):
    _, store, _ = production
    local_key = generate_project_api_key()
    monkeypatch.setenv("DECAUSTRUM_API_KEY", local_key)
    application = main_module.create_app(RuntimeSettings(environment="development"))
    application.dependency_overrides[get_evidence_store] = lambda: store
    with TestClient(application) as client:
        assert store.get_project(DEFAULT_PROJECT_ID) is not None
        assert store.count_project_api_keys(DEFAULT_PROJECT_ID) == 1
        assert (
            client.get("/v1/policies", headers={"X-API-Key": local_key}).status_code
            == 200
        )

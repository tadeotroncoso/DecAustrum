from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api_keys import ProjectApiKeyPrincipal, hash_api_key
from app.evidence_store import EvidenceStore
from app.project_models import Project
from app.security import (
    authenticate_admin,
    authenticate_project,
    get_configured_execution_grant_secret,
    require_project_api_key_role,
)


def build_project() -> Project:
    return Project(
        project_id=uuid4(),
        name="Acme Production",
        status="ACTIVE",
        created_at=datetime.now(timezone.utc),
    )


def test_authenticate_project_returns_project():
    api_key = "dak_valid-project-key"
    project = build_project()
    principal = ProjectApiKeyPrincipal(
        api_key_id=uuid4(),
        role="RUNTIME",
        project=project,
    )

    store = Mock(spec=EvidenceStore)
    store.get_active_api_key_principal_by_hash.return_value = (
        principal
    )

    authenticated_project = authenticate_project(
        provided_api_key=api_key,
        store=store,
    )

    assert authenticated_project == project

    store.get_active_api_key_principal_by_hash.assert_called_once_with(
        hash_api_key(api_key)
    )


def test_authenticate_project_rejects_missing_key():
    store = Mock(spec=EvidenceStore)

    with pytest.raises(HTTPException) as exc_info:
        authenticate_project(
            provided_api_key=None,
            store=store,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == {
        "code": "invalid_api_key",
        "message": "A valid API key is required.",
    }

    store.get_active_api_key_principal_by_hash.assert_not_called()


def test_authenticate_project_rejects_unknown_key():
    store = Mock(spec=EvidenceStore)
    store.get_active_api_key_principal_by_hash.return_value = (
        None
    )

    with pytest.raises(HTTPException) as exc_info:
        authenticate_project(
            provided_api_key="dak_unknown-key",
            store=store,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == {
        "code": "invalid_api_key",
        "message": "A valid API key is required.",
    }


def test_project_api_key_role_rejects_disallowed_operation():
    principal = ProjectApiKeyPrincipal(
        api_key_id=uuid4(),
        role="RUNTIME",
        project=build_project(),
    )

    with pytest.raises(HTTPException) as exc_info:
        require_project_api_key_role(principal, "REVIEWER")

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail["code"] == (
        "insufficient_api_key_role"
    )


def test_authenticate_admin_accepts_matching_key():
    result = authenticate_admin(
        provided_api_key="admin-secret",
        configured_api_key="admin-secret",
    )

    assert result is None


@pytest.mark.parametrize(
    "provided_api_key",
    [None, "wrong-secret"],
)
def test_authenticate_admin_rejects_invalid_key(
    provided_api_key,
):
    with pytest.raises(HTTPException) as exc_info:
        authenticate_admin(
            provided_api_key=provided_api_key,
            configured_api_key="admin-secret",
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == {
        "code": "invalid_admin_api_key",
        "message": (
            "A valid admin API key is required."
        ),
    }


def test_execution_grant_secret_must_be_configured(monkeypatch):
    monkeypatch.delenv(
        "DECAUSTRUM_EXECUTION_GRANT_SECRET",
        raising=False,
    )

    with pytest.raises(RuntimeError, match="must be configured"):
        get_configured_execution_grant_secret()


def test_execution_grant_secret_must_be_strong(monkeypatch):
    monkeypatch.setenv(
        "DECAUSTRUM_EXECUTION_GRANT_SECRET",
        "short",
    )

    with pytest.raises(RuntimeError, match="at least 32 bytes"):
        get_configured_execution_grant_secret()


def test_execution_grant_secret_is_returned(monkeypatch):
    secret = "configured-execution-grant-secret-at-least-32-bytes"
    monkeypatch.setenv("DECAUSTRUM_EXECUTION_GRANT_SECRET", secret)

    assert get_configured_execution_grant_secret() == secret

from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.api_keys import hash_api_key
from app.evidence_store import EvidenceStore
from app.project_models import Project
from app.security import (
    authenticate_admin,
    authenticate_project,
)


def build_project() -> Project:
    return Project(
        project_id=uuid4(),
        name="Acme Production",
        status="ACTIVE",
        created_at=datetime.now(timezone.utc),
    )


def test_authenticate_project_returns_project():
    api_key = "rtk_valid-project-key"
    project = build_project()

    store = Mock(spec=EvidenceStore)
    store.get_active_project_by_api_key_hash.return_value = (
        project
    )

    authenticated_project = authenticate_project(
        provided_api_key=api_key,
        store=store,
    )

    assert authenticated_project == project

    store.get_active_project_by_api_key_hash.assert_called_once_with(
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

    store.get_active_project_by_api_key_hash.assert_not_called()


def test_authenticate_project_rejects_unknown_key():
    store = Mock(spec=EvidenceStore)
    store.get_active_project_by_api_key_hash.return_value = (
        None
    )

    with pytest.raises(HTTPException) as exc_info:
        authenticate_project(
            provided_api_key="rtk_unknown-key",
            store=store,
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == {
        "code": "invalid_api_key",
        "message": "A valid API key is required.",
    }


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

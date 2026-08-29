from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.bootstrap import bootstrap_default_project
from app.evidence_store import EvidenceStore
from app.main import app, get_evidence_store
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID


TEST_API_KEY = "test-api-key"
TEST_ADMIN_API_KEY = "test-admin-api-key"

test_client = TestClient(app)


@pytest.fixture(autouse=True)
def temporary_evidence_store(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "REGTRACE_API_KEY",
        TEST_API_KEY,
    )
    monkeypatch.setenv(
        "REGTRACE_ADMIN_API_KEY",
        TEST_ADMIN_API_KEY,
    )

    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    bootstrap_default_project(
        store=store,
        api_key=TEST_API_KEY,
    )

    store.seed_project_policies(
        project_id=DEFAULT_PROJECT_ID,
        policies=load_policies(POLICIES_DIRECTORY),
        seeded_at=datetime.now(timezone.utc),
    )

    app.dependency_overrides[get_evidence_store] = lambda: store

    yield store

    app.dependency_overrides.clear()


def admin_headers() -> dict[str, str]:
    return {
        "X-Admin-API-Key": TEST_ADMIN_API_KEY,
    }


def project_headers(api_key: str) -> dict[str, str]:
    return {
        "X-API-Key": api_key,
    }


def provision_project(name: str) -> dict:
    response = test_client.post(
        "/v1/admin/projects",
        headers=admin_headers(),
        json={"name": name},
    )

    assert response.status_code == 201

    return response.json()


def change_status(
    project_id: str,
    status: str,
):
    return test_client.patch(
        f"/v1/admin/projects/{project_id}",
        headers=admin_headers(),
        json={"status": status},
    )


def authorize(api_key: str):
    return test_client.post(
        "/v1/authorize",
        headers=project_headers(api_key),
        json={
            "agent": "lifecycle-agent",
            "action": "send_email",
            "context": {},
        },
    )


def test_admin_lists_paginated_and_filtered_projects():
    first = provision_project("First Managed Project")
    second = provision_project("Second Managed Project")
    second_project_id = second["project"]["project_id"]

    disabled_response = change_status(
        second_project_id,
        "DISABLED",
    )

    assert disabled_response.status_code == 200

    first_page = test_client.get(
        "/v1/admin/projects?limit=2&offset=0",
        headers=admin_headers(),
    )
    second_page = test_client.get(
        "/v1/admin/projects?limit=2&offset=2",
        headers=admin_headers(),
    )
    active_page = test_client.get(
        "/v1/admin/projects?status=ACTIVE",
        headers=admin_headers(),
    )
    disabled_page = test_client.get(
        "/v1/admin/projects?status=DISABLED",
        headers=admin_headers(),
    )

    assert first_page.status_code == 200
    assert second_page.status_code == 200
    assert first_page.json()["total"] == 3
    assert second_page.json()["total"] == 3
    assert len(first_page.json()["items"]) == 2
    assert len(second_page.json()["items"]) == 1

    listed_ids = {
        item["project_id"]
        for item in (
            first_page.json()["items"]
            + second_page.json()["items"]
        )
    }

    assert listed_ids == {
        str(DEFAULT_PROJECT_ID),
        first["project"]["project_id"],
        second_project_id,
    }

    assert active_page.status_code == 200
    assert active_page.json()["total"] == 2
    assert {
        item["status"]
        for item in active_page.json()["items"]
    } == {"ACTIVE"}

    assert disabled_page.status_code == 200
    assert disabled_page.json()["total"] == 1
    assert disabled_page.json()["items"][0][
        "project_id"
    ] == second_project_id

    expected_fields = {
        "project_id",
        "name",
        "status",
        "created_at",
        "updated_at",
    }

    assert all(
        set(item) == expected_fields
        for item in first_page.json()["items"]
    )


def test_admin_gets_project_details():
    provisioned = provision_project("Project Details")
    project = provisioned["project"]

    response = test_client.get(
        f"/v1/admin/projects/{project['project_id']}",
        headers=admin_headers(),
    )

    assert response.status_code == 200
    assert response.json() == project
    assert response.json()["updated_at"] == (
        response.json()["created_at"]
    )


def test_disabling_project_is_idempotent_and_blocks_access():
    provisioned = provision_project("Suspended Project")
    project_id = provisioned["project"]["project_id"]
    api_key = provisioned["api_key"]

    first_response = change_status(
        project_id,
        "DISABLED",
    )
    second_response = change_status(
        project_id,
        "DISABLED",
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_response.json()["status"] == "DISABLED"
    assert second_response.json() == first_response.json()
    assert first_response.json()["created_at"] == (
        provisioned["project"]["created_at"]
    )

    authorization_response = authorize(api_key)
    api_key_response = test_client.post(
        f"/v1/admin/projects/{project_id}/api-keys",
        headers=admin_headers(),
    )

    assert authorization_response.status_code == 401
    assert authorization_response.json()["detail"]["code"] == (
        "invalid_api_key"
    )
    assert api_key_response.status_code == 409
    assert api_key_response.json()["detail"]["code"] == (
        "project_disabled"
    )


def test_reactivating_project_restores_non_revoked_key():
    provisioned = provision_project("Reactivated Project")
    project_id = provisioned["project"]["project_id"]

    disabled_response = change_status(
        project_id,
        "DISABLED",
    )
    reactivated_response = change_status(
        project_id,
        "ACTIVE",
    )
    authorization_response = authorize(
        provisioned["api_key"]
    )

    assert disabled_response.status_code == 200
    assert reactivated_response.status_code == 200
    assert reactivated_response.json()["status"] == "ACTIVE"
    assert (
        reactivated_response.json()["updated_at"]
        != disabled_response.json()["updated_at"]
    )
    assert authorization_response.status_code == 200
    assert authorization_response.json()["project_id"] == (
        project_id
    )


def test_reactivation_does_not_restore_revoked_key():
    provisioned = provision_project("Revoked Key Project")
    project_id = provisioned["project"]["project_id"]

    list_response = test_client.get(
        f"/v1/admin/projects/{project_id}/api-keys",
        headers=admin_headers(),
    )
    api_key_id = list_response.json()["items"][0][
        "api_key_id"
    ]

    revoke_response = test_client.delete(
        (
            f"/v1/admin/projects/{project_id}"
            f"/api-keys/{api_key_id}"
        ),
        headers=admin_headers(),
    )

    assert revoke_response.status_code == 200
    assert change_status(
        project_id,
        "DISABLED",
    ).status_code == 200
    assert change_status(
        project_id,
        "ACTIVE",
    ).status_code == 200

    authorization_response = authorize(
        provisioned["api_key"]
    )

    assert authorization_response.status_code == 401


def test_project_lifecycle_rejects_unknown_project():
    project_id = uuid4()

    get_response = test_client.get(
        f"/v1/admin/projects/{project_id}",
        headers=admin_headers(),
    )
    patch_response = change_status(
        str(project_id),
        "DISABLED",
    )

    assert get_response.status_code == 404
    assert get_response.json()["detail"]["code"] == (
        "project_not_found"
    )
    assert patch_response.status_code == 404
    assert patch_response.json()["detail"]["code"] == (
        "project_not_found"
    )


def test_project_lifecycle_validates_status_and_pagination():
    provisioned = provision_project("Validation Project")
    project_id = provisioned["project"]["project_id"]

    invalid_status = change_status(
        project_id,
        "UNKNOWN",
    )
    invalid_limit = test_client.get(
        "/v1/admin/projects?limit=0",
        headers=admin_headers(),
    )
    invalid_offset = test_client.get(
        "/v1/admin/projects?offset=-1",
        headers=admin_headers(),
    )
    project_response = test_client.get(
        f"/v1/admin/projects/{project_id}",
        headers=admin_headers(),
    )

    assert invalid_status.status_code == 422
    assert invalid_limit.status_code == 422
    assert invalid_offset.status_code == 422
    assert project_response.json()["status"] == "ACTIVE"


def test_default_project_cannot_be_disabled():
    response = change_status(
        str(DEFAULT_PROJECT_ID),
        "DISABLED",
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "default_project_protected",
        "message": "The default project cannot be disabled.",
    }
    assert authorize(TEST_API_KEY).status_code == 200


def test_project_api_key_cannot_manage_project_lifecycle():
    provisioned = provision_project("Tenant Managed Project")
    project_id = provisioned["project"]["project_id"]
    headers = project_headers(provisioned["api_key"])

    list_response = test_client.get(
        "/v1/admin/projects",
        headers=headers,
    )
    get_response = test_client.get(
        f"/v1/admin/projects/{project_id}",
        headers=headers,
    )
    patch_response = test_client.patch(
        f"/v1/admin/projects/{project_id}",
        headers=headers,
        json={"status": "DISABLED"},
    )

    assert list_response.status_code == 401
    assert get_response.status_code == 401
    assert patch_response.status_code == 401
    assert patch_response.json()["detail"]["code"] == (
        "invalid_admin_api_key"
    )

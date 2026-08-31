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
        "DECAUSTRUM_API_KEY",
        TEST_API_KEY,
    )
    monkeypatch.setenv(
        "DECAUSTRUM_ADMIN_API_KEY",
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


def build_refund_policy(
    *,
    version: int,
    amount: int,
    decision: str = "REQUIRE_APPROVAL",
) -> dict:
    return {
        "id": "refund-limit",
        "version": version,
        "action": "refund_payment",
        "match": "all",
        "conditions": [
            {
                "field": "amount",
                "operator": "greater_than",
                "value": amount,
            }
        ],
        "decision": decision,
        "reason": (
            f"Project refunds above {amount} produce "
            f"{decision}."
        ),
    }


def policy_url(project_id: str) -> str:
    return (
        f"/v1/admin/projects/{project_id}"
        "/policies/refund-limit"
    )


def history_url(project_id: str) -> str:
    return f"{policy_url(project_id)}/versions"


def update_refund_policy(
    project_id: str,
    *,
    version: int = 2,
    amount: int = 100,
    decision: str = "DENY",
):
    return test_client.put(
        policy_url(project_id),
        headers=admin_headers(),
        json=build_refund_policy(
            version=version,
            amount=amount,
            decision=decision,
        ),
    )


def rollback_refund_policy(
    project_id: str,
    version: int,
):
    return test_client.post(
        f"{policy_url(project_id)}/rollback",
        headers=admin_headers(),
        json={"version": version},
    )


def authorize_refund(api_key: str, amount: int):
    return test_client.post(
        "/v1/authorize",
        headers=project_headers(api_key),
        json={
            "agent": "refund-agent",
            "action": "refund_payment",
            "context": {"amount": amount},
        },
    )


def test_admin_can_list_and_get_policy_versions():
    provisioned = provision_project("History Reader")
    project_id = provisioned["project"]["project_id"]

    list_response = test_client.get(
        history_url(project_id),
        headers=admin_headers(),
    )

    assert list_response.status_code == 200
    page = list_response.json()
    assert page["total"] == 1
    assert page["limit"] == 20
    assert page["offset"] == 0

    version = page["items"][0]
    assert version["project_id"] == project_id
    assert version["policy_id"] == "refund-limit"
    assert version["version"] == 1
    assert version["policy"]["id"] == "refund-limit"
    assert version["policy"]["version"] == 1
    assert version["change_type"] == "CREATED"
    assert version["source_version"] is None

    get_response = test_client.get(
        f"{history_url(project_id)}/1",
        headers=admin_headers(),
    )

    assert get_response.status_code == 200
    assert get_response.json() == version


def test_policy_update_appends_without_changing_version_one():
    provisioned = provision_project("History Writer")
    project_id = provisioned["project"]["project_id"]

    update_response = update_refund_policy(project_id)
    history_response = test_client.get(
        history_url(project_id),
        headers=admin_headers(),
    )

    assert update_response.status_code == 200
    assert history_response.status_code == 200
    versions = history_response.json()["items"]
    assert [entry["version"] for entry in versions] == [2, 1]
    assert versions[0]["change_type"] == "UPDATED"
    assert versions[0]["policy"]["conditions"][0][
        "value"
    ] == 100
    assert versions[1]["change_type"] == "CREATED"
    assert versions[1]["policy"]["conditions"][0][
        "value"
    ] == 500


def test_rollback_restores_behavior_as_new_version():
    provisioned = provision_project("Rollback Project")
    project_id = provisioned["project"]["project_id"]
    api_key = provisioned["api_key"]

    update_response = update_refund_policy(project_id)
    before_rollback = authorize_refund(api_key, amount=200)
    rollback_response = rollback_refund_policy(
        project_id,
        version=1,
    )
    after_rollback = authorize_refund(api_key, amount=200)
    history_response = test_client.get(
        history_url(project_id),
        headers=admin_headers(),
    )

    assert update_response.status_code == 200
    assert before_rollback.status_code == 200
    assert before_rollback.json()["decision"] == "DENY"
    assert before_rollback.json()["policy_version"] == 2

    assert rollback_response.status_code == 200
    rolled_back = rollback_response.json()
    assert rolled_back["enabled"] is True
    assert rolled_back["policy"]["version"] == 3
    assert rolled_back["policy"]["conditions"][0][
        "value"
    ] == 500
    assert rolled_back["policy"]["decision"] == (
        "REQUIRE_APPROVAL"
    )

    assert after_rollback.status_code == 200
    assert after_rollback.json()["decision"] == "ALLOW"

    versions = history_response.json()["items"]
    assert [entry["version"] for entry in versions] == [3, 2, 1]
    assert versions[0]["change_type"] == "ROLLBACK"
    assert versions[0]["source_version"] == 1
    assert versions[1]["change_type"] == "UPDATED"
    assert versions[1]["policy"]["conditions"][0][
        "value"
    ] == 100
    assert versions[2]["change_type"] == "CREATED"


def test_rollback_reenables_a_disabled_policy():
    provisioned = provision_project("Restore Disabled")
    project_id = provisioned["project"]["project_id"]

    update_refund_policy(project_id)
    disable_response = test_client.delete(
        policy_url(project_id),
        headers=admin_headers(),
    )
    rollback_response = rollback_refund_policy(
        project_id,
        version=1,
    )
    tenant_response = test_client.get(
        "/v1/policies/refund-limit",
        headers=project_headers(provisioned["api_key"]),
    )

    assert disable_response.status_code == 200
    assert disable_response.json()["enabled"] is False
    assert rollback_response.status_code == 200
    assert rollback_response.json()["enabled"] is True
    assert rollback_response.json()["policy"]["version"] == 3
    assert tenant_response.status_code == 200
    assert tenant_response.json()["version"] == 3


def test_policy_history_is_paginated_and_validated():
    provisioned = provision_project("Paged History")
    project_id = provisioned["project"]["project_id"]
    update_refund_policy(project_id)
    rollback_refund_policy(project_id, version=1)

    response = test_client.get(
        f"{history_url(project_id)}?limit=1&offset=1",
        headers=admin_headers(),
    )
    invalid_limit = test_client.get(
        f"{history_url(project_id)}?limit=0",
        headers=admin_headers(),
    )
    invalid_offset = test_client.get(
        f"{history_url(project_id)}?offset=-1",
        headers=admin_headers(),
    )
    invalid_version = test_client.get(
        f"{history_url(project_id)}/0",
        headers=admin_headers(),
    )
    invalid_rollback = rollback_refund_policy(
        project_id,
        version=0,
    )

    assert response.status_code == 200
    assert response.json()["total"] == 3
    assert response.json()["limit"] == 1
    assert response.json()["offset"] == 1
    assert response.json()["items"][0]["version"] == 2
    assert invalid_limit.status_code == 422
    assert invalid_offset.status_code == 422
    assert invalid_version.status_code == 422
    assert invalid_rollback.status_code == 422


def test_policy_history_is_isolated_between_projects():
    first = provision_project("First History")
    second = provision_project("Second History")
    first_project_id = first["project"]["project_id"]
    second_project_id = second["project"]["project_id"]

    update_refund_policy(first_project_id)

    first_history = test_client.get(
        history_url(first_project_id),
        headers=admin_headers(),
    )
    second_history = test_client.get(
        history_url(second_project_id),
        headers=admin_headers(),
    )
    hidden_version = test_client.get(
        f"{history_url(second_project_id)}/2",
        headers=admin_headers(),
    )
    hidden_rollback = rollback_refund_policy(
        second_project_id,
        version=2,
    )

    assert first_history.json()["total"] == 2
    assert second_history.json()["total"] == 1
    assert hidden_version.status_code == 404
    assert hidden_version.json()["detail"]["code"] == (
        "policy_version_not_found"
    )
    assert hidden_rollback.status_code == 404
    assert hidden_rollback.json()["detail"]["code"] == (
        "policy_version_not_found"
    )


def test_policy_history_returns_specific_missing_errors():
    provisioned = provision_project("Missing History")
    project_id = provisioned["project"]["project_id"]
    unknown_project_id = uuid4()

    unknown_project = test_client.get(
        history_url(str(unknown_project_id)),
        headers=admin_headers(),
    )
    unknown_policy = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/missing-policy/versions"
        ),
        headers=admin_headers(),
    )
    unknown_version = test_client.get(
        f"{history_url(project_id)}/99",
        headers=admin_headers(),
    )

    assert unknown_project.status_code == 404
    assert unknown_project.json()["detail"]["code"] == (
        "project_not_found"
    )
    assert unknown_policy.status_code == 404
    assert unknown_policy.json()["detail"]["code"] == (
        "policy_not_found"
    )
    assert unknown_version.status_code == 404
    assert unknown_version.json()["detail"] == {
        "code": "policy_version_not_found",
        "message": (
            "Policy 'refund-limit' version 99 was not found."
        ),
        "policy_id": "refund-limit",
        "version": 99,
    }


def test_rollback_rejects_the_current_version():
    provisioned = provision_project("Current Version")
    project_id = provisioned["project"]["project_id"]

    response = rollback_refund_policy(project_id, version=1)

    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "policy_version_already_current",
        "message": (
            "Policy 'refund-limit' is already at version 1."
        ),
        "policy_id": "refund-limit",
        "version": 1,
    }


def test_project_api_key_cannot_access_policy_history():
    provisioned = provision_project("Tenant History")
    project_id = provisioned["project"]["project_id"]
    headers = project_headers(provisioned["api_key"])

    list_response = test_client.get(
        history_url(project_id),
        headers=headers,
    )
    get_response = test_client.get(
        f"{history_url(project_id)}/1",
        headers=headers,
    )
    rollback_response = test_client.post(
        f"{policy_url(project_id)}/rollback",
        headers=headers,
        json={"version": 1},
    )

    assert list_response.status_code == 401
    assert get_response.status_code == 401
    assert rollback_response.status_code == 401
    assert list_response.json()["detail"]["code"] == (
        "invalid_admin_api_key"
    )

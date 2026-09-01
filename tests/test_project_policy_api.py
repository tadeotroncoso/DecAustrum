import json
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
            f"Project-specific refunds above {amount} "
            f"produce {decision}."
        ),
    }


def authorize_refund(
    api_key: str,
    amount: int,
):
    return test_client.post(
        "/v1/authorize",
        headers=project_headers(api_key),
        json={
            "agent": "refund-agent",
            "action": "refund_payment",
            "context": {"amount": amount},
        },
    )


def test_new_project_inherits_policy_templates():
    provisioned = provision_project("Inherited Policies")
    project_id = provisioned["project"]["project_id"]

    admin_response = test_client.get(
        f"/v1/admin/projects/{project_id}/policies",
        headers=admin_headers(),
    )
    tenant_response = test_client.get(
        "/v1/policies",
        headers=project_headers(provisioned["api_key"]),
    )

    assert admin_response.status_code == 200
    assert tenant_response.status_code == 200

    expected_ids = {
        policy.id
        for policy in load_policies(POLICIES_DIRECTORY)
    }
    admin_data = admin_response.json()
    tenant_data = tenant_response.json()

    assert admin_data["total"] == len(expected_ids)
    assert {
        item["policy"]["id"]
        for item in admin_data["items"]
    } == expected_ids
    assert all(
        item["enabled"]
        for item in admin_data["items"]
    )
    assert {
        item["id"]
        for item in tenant_data["items"]
    } == expected_ids


def test_policy_update_is_isolated_between_projects():
    first = provision_project("Strict Refunds")
    second = provision_project("Standard Refunds")
    first_project_id = first["project"]["project_id"]

    update_response = test_client.put(
        (
            f"/v1/admin/projects/{first_project_id}"
            "/policies/refund-limit"
        ),
        headers=admin_headers(),
        json=build_refund_policy(
            version=2,
            amount=100,
            decision="DENY",
        ),
    )

    assert update_response.status_code == 200
    assert update_response.json()["enabled"] is True
    assert update_response.json()["policy"]["version"] == 2

    first_authorization = authorize_refund(
        first["api_key"],
        200,
    )
    second_authorization = authorize_refund(
        second["api_key"],
        200,
    )
    default_authorization = authorize_refund(
        TEST_API_KEY,
        200,
    )

    assert first_authorization.status_code == 200
    assert first_authorization.json()["decision"] == "DENY"
    assert first_authorization.json()["policy"] == "refund-limit"
    assert first_authorization.json()["policy_version"] == 2

    assert second_authorization.status_code == 200
    assert second_authorization.json()["decision"] == "ALLOW"
    assert default_authorization.status_code == 200
    assert default_authorization.json()["decision"] == "ALLOW"

    first_policy = test_client.get(
        "/v1/policies/refund-limit",
        headers=project_headers(first["api_key"]),
    )
    second_policy = test_client.get(
        "/v1/policies/refund-limit",
        headers=project_headers(second["api_key"]),
    )

    assert first_policy.json()["version"] == 2
    assert second_policy.json()["version"] == 1


def test_policy_api_rejects_non_finite_condition_value():
    provisioned = provision_project("Finite Policy Values")
    project_id = provisioned["project"]["project_id"]
    policy = build_refund_policy(version=2, amount=100)
    policy["conditions"][0]["value"] = float("nan")

    response = test_client.put(
        f"/v1/admin/projects/{project_id}/policies/refund-limit",
        headers={
            **admin_headers(),
            "Content-Type": "application/json",
        },
        content=json.dumps(policy),
    )

    assert response.status_code == 422


def test_disabling_policy_is_isolated_and_idempotent():
    first = provision_project("Policy Disabled")
    second = provision_project("Policy Enabled")
    first_project_id = first["project"]["project_id"]
    policy_url = (
        f"/v1/admin/projects/{first_project_id}"
        "/policies/refund-limit"
    )

    first_delete = test_client.delete(
        policy_url,
        headers=admin_headers(),
    )
    second_delete = test_client.delete(
        policy_url,
        headers=admin_headers(),
    )

    assert first_delete.status_code == 200
    assert second_delete.status_code == 200
    assert first_delete.json()["enabled"] is False
    assert second_delete.json()["enabled"] is False
    assert (
        second_delete.json()["updated_at"]
        == first_delete.json()["updated_at"]
    )

    admin_get = test_client.get(
        policy_url,
        headers=admin_headers(),
    )
    first_tenant_get = test_client.get(
        "/v1/policies/refund-limit",
        headers=project_headers(first["api_key"]),
    )
    second_tenant_get = test_client.get(
        "/v1/policies/refund-limit",
        headers=project_headers(second["api_key"]),
    )

    assert admin_get.status_code == 200
    assert admin_get.json()["enabled"] is False
    assert first_tenant_get.status_code == 404
    assert second_tenant_get.status_code == 200

    first_authorization = authorize_refund(
        first["api_key"],
        750,
    )
    second_authorization = authorize_refund(
        second["api_key"],
        750,
    )

    assert first_authorization.json()["decision"] == "ALLOW"
    assert (
        second_authorization.json()["decision"]
        == "REQUIRE_APPROVAL"
    )


def test_disabled_policy_can_be_reactivated_with_next_version():
    provisioned = provision_project("Reactivated Policy")
    project_id = provisioned["project"]["project_id"]
    policy_url = (
        f"/v1/admin/projects/{project_id}"
        "/policies/refund-limit"
    )

    disable_response = test_client.delete(
        policy_url,
        headers=admin_headers(),
    )
    reactivate_response = test_client.put(
        policy_url,
        headers=admin_headers(),
        json=build_refund_policy(
            version=2,
            amount=200,
        ),
    )

    assert disable_response.status_code == 200
    assert reactivate_response.status_code == 200
    assert reactivate_response.json()["enabled"] is True
    assert reactivate_response.json()["policy"]["version"] == 2

    authorization = authorize_refund(
        provisioned["api_key"],
        300,
    )

    assert authorization.status_code == 200
    assert (
        authorization.json()["decision"]
        == "REQUIRE_APPROVAL"
    )
    assert authorization.json()["policy_version"] == 2


@pytest.mark.parametrize("version", [1, 3])
def test_policy_update_requires_exact_next_version(version):
    provisioned = provision_project("Versioned Policies")
    project_id = provisioned["project"]["project_id"]

    response = test_client.put(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/refund-limit"
        ),
        headers=admin_headers(),
        json=build_refund_policy(
            version=version,
            amount=100,
        ),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {
        "code": "policy_version_conflict",
        "message": (
            "Policy 'refund-limit' must use version "
            f"2, not {version}."
        ),
        "expected_version": 2,
        "provided_version": version,
    }


def test_new_policy_must_start_at_version_one():
    provisioned = provision_project("Custom Policies")
    project_id = provisioned["project"]["project_id"]
    policy_url = (
        f"/v1/admin/projects/{project_id}"
        "/policies/custom-export-control"
    )
    policy = {
        "id": "custom-export-control",
        "version": 2,
        "action": "export_report",
        "match": "all",
        "conditions": [
            {
                "field": "row_count",
                "operator": "greater_than",
                "value": 10,
            }
        ],
        "decision": "DENY",
        "reason": "Large report exports are denied.",
    }

    invalid_response = test_client.put(
        policy_url,
        headers=admin_headers(),
        json=policy,
    )

    assert invalid_response.status_code == 409
    assert invalid_response.json()["detail"][
        "expected_version"
    ] == 1

    policy["version"] = 1

    create_response = test_client.put(
        policy_url,
        headers=admin_headers(),
        json=policy,
    )
    authorization = test_client.post(
        "/v1/authorize",
        headers=project_headers(provisioned["api_key"]),
        json={
            "agent": "report-agent",
            "action": "export_report",
            "context": {"row_count": 11},
        },
    )

    assert create_response.status_code == 200
    assert create_response.json()["enabled"] is True
    assert authorization.status_code == 200
    assert authorization.json()["decision"] == "DENY"
    assert authorization.json()["policy"] == (
        "custom-export-control"
    )


def test_policy_path_and_body_ids_must_match():
    provisioned = provision_project("Mismatched Policy")
    project_id = provisioned["project"]["project_id"]

    response = test_client.put(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/different-id"
        ),
        headers=admin_headers(),
        json=build_refund_policy(
            version=2,
            amount=100,
        ),
    )

    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "policy_id_mismatch",
        "message": (
            "Policy ID 'refund-limit' does not match "
            "path policy ID 'different-id'."
        ),
        "path_policy_id": "different-id",
        "body_policy_id": "refund-limit",
    }


def test_admin_policy_routes_reject_unknown_resources():
    provisioned = provision_project("Known Project")
    project_id = provisioned["project"]["project_id"]
    unknown_project_id = uuid4()

    unknown_project_response = test_client.get(
        (
            f"/v1/admin/projects/{unknown_project_id}"
            "/policies"
        ),
        headers=admin_headers(),
    )
    unknown_policy_response = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/missing-policy"
        ),
        headers=admin_headers(),
    )
    unknown_delete_response = test_client.delete(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/missing-policy"
        ),
        headers=admin_headers(),
    )

    assert unknown_project_response.status_code == 404
    assert unknown_project_response.json()["detail"]["code"] == (
        "project_not_found"
    )
    assert unknown_policy_response.status_code == 404
    assert unknown_policy_response.json()["detail"]["code"] == (
        "policy_not_found"
    )
    assert unknown_delete_response.status_code == 404
    assert unknown_delete_response.json()["detail"]["code"] == (
        "policy_not_found"
    )


def test_project_api_key_cannot_manage_policies():
    provisioned = provision_project("Tenant Cannot Configure")
    project_id = provisioned["project"]["project_id"]

    response = test_client.put(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/refund-limit"
        ),
        headers=project_headers(provisioned["api_key"]),
        json=build_refund_policy(
            version=2,
            amount=100,
        ),
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == (
        "invalid_admin_api_key"
    )

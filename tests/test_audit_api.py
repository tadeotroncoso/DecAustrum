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
    monkeypatch.setenv("REGTRACE_API_KEY", TEST_API_KEY)
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


def admin_headers(
    actor: str = "security-admin",
    reason: str = "Administrative security change.",
) -> dict[str, str]:
    return {
        "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        "X-Admin-Actor": actor,
        "X-Audit-Reason": reason,
    }


def project_headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


def provision_project(
    name: str,
    *,
    actor: str = "security-admin",
    reason: str = "Project onboarding.",
) -> dict:
    response = test_client.post(
        "/v1/admin/projects",
        headers=admin_headers(actor, reason),
        json={"name": name},
    )
    assert response.status_code == 201
    return response.json()


def audit_events(project_id: str, **params) -> dict:
    response = test_client.get(
        "/v1/admin/audit-events",
        headers=admin_headers(),
        params={"project_id": project_id, **params},
    )
    assert response.status_code == 200
    return response.json()


def refund_policy_v2() -> dict:
    policy = next(
        policy
        for policy in load_policies(POLICIES_DIRECTORY)
        if policy.id == "refund-limit"
    ).model_dump(mode="json")
    policy["version"] = 2
    policy["conditions"][0]["value"] = 100
    return policy


def test_project_provisioning_audits_actor_reason_and_safe_data():
    provisioned = provision_project(
        "Audited Project",
        actor="alice@example.com",
        reason="Customer onboarding ticket SEC-42.",
    )
    project = provisioned["project"]
    events = audit_events(project["project_id"])["items"]
    actions = [event["action"] for event in events]

    assert "PROJECT_CREATED" in actions
    assert "API_KEY_CREATED" in actions
    assert actions.count("POLICY_CREATED") == len(
        load_policies(POLICIES_DIRECTORY)
    )
    assert all(
        event["actor_type"] == "ADMIN"
        and event["actor_id"] == "alice@example.com"
        and event["reason"]
        == "Customer onboarding ticket SEC-42."
        for event in events
    )

    project_event = next(
        event
        for event in events
        if event["action"] == "PROJECT_CREATED"
    )
    key_event = next(
        event
        for event in events
        if event["action"] == "API_KEY_CREATED"
    )

    assert project_event["before"] is None
    assert project_event["after"] == project
    assert key_event["before"] is None
    assert set(key_event["after"]) == {
        "api_key_id",
        "project_id",
        "key_prefix",
        "created_at",
        "revoked_at",
    }
    serialized_key_event = str(key_event)
    assert "key_hash" not in serialized_key_event
    assert provisioned["api_key"] not in serialized_key_event


def test_project_and_api_key_lifecycle_events_are_idempotent():
    provisioned = provision_project("Lifecycle Audit")
    project_id = provisioned["project"]["project_id"]
    headers = admin_headers(
        "lifecycle-admin",
        "Lifecycle maintenance.",
    )

    for _ in range(2):
        response = test_client.patch(
            f"/v1/admin/projects/{project_id}",
            headers=headers,
            json={"status": "DISABLED"},
        )
        assert response.status_code == 200

    test_client.patch(
        f"/v1/admin/projects/{project_id}",
        headers=headers,
        json={"status": "ACTIVE"},
    )
    key_response = test_client.post(
        f"/v1/admin/projects/{project_id}/api-keys",
        headers=headers,
    )
    assert key_response.status_code == 201
    api_key_id = key_response.json()["key"]["api_key_id"]

    for _ in range(2):
        response = test_client.delete(
            (
                f"/v1/admin/projects/{project_id}"
                f"/api-keys/{api_key_id}"
            ),
            headers=headers,
        )
        assert response.status_code == 200

    events = audit_events(project_id)["items"]

    assert sum(
        event["action"] == "PROJECT_STATUS_CHANGED"
        for event in events
    ) == 2
    assert sum(
        event["action"] == "API_KEY_REVOKED"
        for event in events
    ) == 1
    revoked = next(
        event
        for event in events
        if event["action"] == "API_KEY_REVOKED"
    )
    assert revoked["before"]["revoked_at"] is None
    assert revoked["after"]["revoked_at"] is not None


def test_complete_policy_lifecycle_is_audited():
    provisioned = provision_project("Policy Audit")
    project_id = provisioned["project"]["project_id"]
    url = (
        f"/v1/admin/projects/{project_id}"
        "/policies/refund-limit"
    )
    headers = admin_headers(
        "policy-admin",
        "Policy control ticket POL-7.",
    )

    assert test_client.put(
        url,
        headers=headers,
        json=refund_policy_v2(),
    ).status_code == 200
    assert test_client.delete(
        url,
        headers=headers,
    ).status_code == 200
    assert test_client.delete(
        url,
        headers=headers,
    ).status_code == 200
    rollback = test_client.post(
        f"{url}/rollback",
        headers=headers,
        json={"version": 1},
    )
    assert rollback.status_code == 200

    events = audit_events(
        project_id,
        resource_type="POLICY",
        resource_id="refund-limit",
    )["items"]
    actions = [event["action"] for event in events]

    assert actions.count("POLICY_CREATED") == 1
    assert actions.count("POLICY_UPDATED") == 1
    assert actions.count("POLICY_DISABLED") == 1
    assert actions.count("POLICY_ROLLED_BACK") == 1
    rollback_event = next(
        event
        for event in events
        if event["action"] == "POLICY_ROLLED_BACK"
    )
    assert rollback_event["metadata"] == {
        "new_version": 3,
        "source_version": 1,
    }
    assert rollback_event["before"]["enabled"] is False
    assert rollback_event["after"]["enabled"] is True


def test_approval_resolution_is_audited_with_project_actor():
    provisioned = provision_project("Approval Audit")
    project_id = provisioned["project"]["project_id"]
    authorization = test_client.post(
        "/v1/authorize",
        headers=project_headers(provisioned["api_key"]),
        json={
            "agent": "refund-agent",
            "action": "refund_payment",
            "context": {"amount": 750},
        },
    )
    assert authorization.status_code == 200
    decision_id = authorization.json()["decision_id"]

    resolution = test_client.post(
        f"/v1/approvals/{decision_id}/approve",
        headers=project_headers(provisioned["api_key"]),
        json={
            "resolved_by": "finance-reviewer",
            "reason": "Customer evidence verified.",
        },
    )
    assert resolution.status_code == 200

    events = audit_events(
        project_id,
        action="APPROVAL_RESOLVED",
    )["items"]
    assert len(events) == 1
    event = events[0]
    assert event["actor_type"] == "PROJECT"
    assert event["actor_id"] == "finance-reviewer"
    assert event["reason"] == "Customer evidence verified."
    assert event["resource_id"] == decision_id
    assert event["before"]["status"] == "PENDING"
    assert event["after"]["status"] == "APPROVED"


def test_audit_api_filters_paginates_and_gets_exact_event():
    provisioned = provision_project(
        "Queryable Audit",
        actor="query-admin",
    )
    project_id = provisioned["project"]["project_id"]
    page = test_client.get(
        "/v1/admin/audit-events",
        headers=admin_headers(),
        params={
            "project_id": project_id,
            "actor_type": "ADMIN",
            "actor_id": "query-admin",
            "limit": 1,
            "offset": 0,
        },
    )

    assert page.status_code == 200
    assert page.json()["total"] >= 2
    assert len(page.json()["items"]) == 1
    event = page.json()["items"][0]

    exact = test_client.get(
        f"/v1/admin/audit-events/{event['event_id']}",
        headers=admin_headers(),
    )
    ranged = test_client.get(
        "/v1/admin/audit-events",
        headers=admin_headers(),
        params={
            "project_id": project_id,
            "occurred_after": event["occurred_at"],
            "occurred_before": event["occurred_at"],
        },
    )

    assert exact.status_code == 200
    assert exact.json() == event
    assert ranged.status_code == 200
    assert ranged.json()["total"] >= 1


def test_audit_api_rejects_invalid_queries_and_headers():
    invalid_action = test_client.get(
        "/v1/admin/audit-events?action=BANANA",
        headers=admin_headers(),
    )
    invalid_page = test_client.get(
        "/v1/admin/audit-events?limit=0",
        headers=admin_headers(),
    )
    naive_time = test_client.get(
        (
            "/v1/admin/audit-events"
            "?occurred_after=2026-08-29T12:00:00"
        ),
        headers=admin_headers(),
    )
    inverted = test_client.get(
        "/v1/admin/audit-events",
        headers=admin_headers(),
        params={
            "occurred_after": "2030-01-01T00:00:00Z",
            "occurred_before": "2020-01-01T00:00:00Z",
        },
    )
    blank_actor_headers = admin_headers()
    blank_actor_headers["X-Admin-Actor"] = "   "
    blank_actor = test_client.post(
        "/v1/admin/projects",
        headers=blank_actor_headers,
        json={"name": "Invalid Actor"},
    )

    assert invalid_action.status_code == 422
    assert invalid_page.status_code == 422
    assert naive_time.status_code == 422
    assert naive_time.json()["detail"]["code"] == (
        "audit_timezone_required"
    )
    assert inverted.status_code == 422
    assert inverted.json()["detail"]["code"] == (
        "invalid_audit_time_range"
    )
    assert blank_actor.status_code == 422


def test_failed_admin_mutation_does_not_emit_audit_event():
    provisioned = provision_project("Failed Audit Mutation")
    project_id = provisioned["project"]["project_id"]
    invalid_policy = refund_policy_v2()
    invalid_policy["version"] = 1

    response = test_client.put(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/refund-limit"
        ),
        headers=admin_headers(),
        json=invalid_policy,
    )
    updated_events = audit_events(
        project_id,
        action="POLICY_UPDATED",
    )

    assert response.status_code == 409
    assert updated_events["total"] == 0


def test_audit_endpoints_require_admin_access_and_return_404():
    no_key = test_client.get("/v1/admin/audit-events")
    tenant_key = test_client.get(
        "/v1/admin/audit-events",
        headers=project_headers(TEST_API_KEY),
    )
    event_id = uuid4()
    missing = test_client.get(
        f"/v1/admin/audit-events/{event_id}",
        headers=admin_headers(),
    )

    assert no_key.status_code == 401
    assert tenant_key.status_code == 401
    assert missing.status_code == 404
    assert missing.json()["detail"] == {
        "code": "audit_event_not_found",
        "message": (
            f"Administrative audit event '{event_id}' "
            "was not found."
        ),
    }

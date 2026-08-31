from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.bootstrap import bootstrap_default_project
from app.dependencies import (
    get_evidence_store,
    get_webhook_transport,
)
from app.evidence_store import EvidenceStore
from app.main import app
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID
from app.webhooks import (
    WebhookHttpResponse,
    verify_webhook_signature,
)

TEST_API_KEY = "test-api-key"
TEST_ADMIN_API_KEY = "test-admin-api-key"
TEST_MASTER_SECRET = "webhook-api-master-secret-value-123"

test_client = TestClient(app)


class ApiRecordingTransport:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.requests = []

    def send(
        self,
        *,
        url,
        body,
        headers,
        timeout_seconds,
    ):
        self.requests.append(
            {
                "url": url,
                "body": body,
                "headers": headers,
                "timeout_seconds": timeout_seconds,
            }
        )
        return WebhookHttpResponse(
            status_code=self.status_code
        )


@pytest.fixture(autouse=True)
def temporary_evidence_store(tmp_path, monkeypatch):
    monkeypatch.setenv("DECAUSTRUM_API_KEY", TEST_API_KEY)
    monkeypatch.setenv(
        "DECAUSTRUM_ADMIN_API_KEY",
        TEST_ADMIN_API_KEY,
    )
    monkeypatch.setenv(
        "DECAUSTRUM_WEBHOOK_MASTER_SECRET",
        TEST_MASTER_SECRET,
    )
    monkeypatch.setenv(
        "DECAUSTRUM_EXECUTION_GRANT_SECRET",
        "test-execution-grant-secret-at-least-32-bytes",
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
    transport = ApiRecordingTransport()
    app.dependency_overrides[get_evidence_store] = lambda: store
    app.dependency_overrides[get_webhook_transport] = (
        lambda: transport
    )

    yield store, transport

    app.dependency_overrides.clear()


def admin_headers() -> dict[str, str]:
    return {
        "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        "X-Admin-Actor": "webhook-admin",
        "X-Audit-Reason": "Webhook configuration ticket WH-42.",
    }


def provision_project(name: str) -> dict:
    response = test_client.post(
        "/v1/admin/projects",
        headers=admin_headers(),
        json={"name": name},
    )
    assert response.status_code == 201
    return response.json()


def create_subscription(
    project_id: str,
    event_types=None,
) -> dict:
    body = {"url": "https://hooks.example.com/decaustrum"}

    if event_types is not None:
        body["event_types"] = event_types

    response = test_client.post(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-subscriptions"
        ),
        headers=admin_headers(),
        json=body,
    )
    assert response.status_code == 201
    return response.json()


def test_subscription_lifecycle_returns_secret_only_when_needed(
    temporary_evidence_store,
):
    store, _ = temporary_evidence_store
    provisioned = provision_project("Webhook Lifecycle")
    project_id = provisioned["project"]["project_id"]
    created = create_subscription(project_id)
    subscription = created["subscription"]
    subscription_id = subscription["subscription_id"]

    listed = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-subscriptions"
        ),
        headers=admin_headers(),
    )
    fetched = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            f"/webhook-subscriptions/{subscription_id}"
        ),
        headers=admin_headers(),
    )
    rotated = test_client.post(
        (
            f"/v1/admin/projects/{project_id}"
            f"/webhook-subscriptions/{subscription_id}"
            "/rotate-secret"
        ),
        headers=admin_headers(),
    )

    assert created["signing_secret"].startswith("whsec_")
    assert listed.status_code == 200
    assert fetched.status_code == 200
    assert "signing_secret" not in str(listed.json())
    assert "signing_secret" not in str(fetched.json())
    assert rotated.status_code == 200
    assert rotated.json()["signing_secret"] != (
        created["signing_secret"]
    )
    assert rotated.json()["subscription"]["secret_version"] == 2

    disabled = test_client.delete(
        (
            f"/v1/admin/projects/{project_id}"
            f"/webhook-subscriptions/{subscription_id}"
        ),
        headers=admin_headers(),
    )
    repeated = test_client.delete(
        (
            f"/v1/admin/projects/{project_id}"
            f"/webhook-subscriptions/{subscription_id}"
        ),
        headers=admin_headers(),
    )
    rotate_disabled = test_client.post(
        (
            f"/v1/admin/projects/{project_id}"
            f"/webhook-subscriptions/{subscription_id}"
            "/rotate-secret"
        ),
        headers=admin_headers(),
    )

    assert disabled.status_code == 200
    assert repeated.status_code == 200
    assert disabled.json() == repeated.json()
    assert disabled.json()["status"] == "DISABLED"
    assert rotate_disabled.status_code == 409
    assert rotate_disabled.json()["detail"]["code"] == (
        "webhook_subscription_disabled"
    )
    assert store.count_administrative_audit_events(
        project_id=subscription["project_id"],
        action="WEBHOOK_SUBSCRIPTION_CREATED",
    ) == 1
    assert store.count_administrative_audit_events(
        project_id=subscription["project_id"],
        action="WEBHOOK_SECRET_ROTATED",
    ) == 1
    assert store.count_administrative_audit_events(
        project_id=subscription["project_id"],
        action="WEBHOOK_SUBSCRIPTION_DISABLED",
    ) == 1


def test_authorization_outbox_is_idempotent_and_dispatchable(
    temporary_evidence_store,
):
    _, transport = temporary_evidence_store
    provisioned = provision_project("Webhook Authorization")
    project_id = provisioned["project"]["project_id"]
    api_key = provisioned["api_key"]
    created = create_subscription(
        project_id,
        ["authorization.created"],
    )

    headers = {
        "X-API-Key": api_key,
        "Idempotency-Key": "authorize-webhook-1",
    }
    body = {
        "agent": "finance-agent",
        "action": "refund_payment",
        "context": {"amount": 300},
    }
    first = test_client.post(
        "/v1/authorize",
        headers=headers,
        json=body,
    )
    repeated = test_client.post(
        "/v1/authorize",
        headers=headers,
        json=body,
    )
    events = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-events"
        ),
        headers=admin_headers(),
        params={"event_type": "authorization.created"},
    )
    deliveries = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-deliveries"
        ),
        headers=admin_headers(),
    )

    assert first.status_code == 200
    assert repeated.status_code == 200
    assert repeated.json() == first.json()
    assert events.status_code == 200
    assert events.json()["total"] == 1
    assert deliveries.json()["total"] == 1

    dispatched = test_client.post(
        "/v1/admin/webhook-deliveries/dispatch",
        headers=admin_headers(),
    )

    assert dispatched.status_code == 200
    assert dispatched.json()["delivered"] == 1
    assert len(transport.requests) == 1
    request = transport.requests[0]
    assert verify_webhook_signature(
        payload=request["body"],
        timestamp=request["headers"]["X-DecAustrum-Timestamp"],
        signature=request["headers"]["X-DecAustrum-Signature"],
        signing_secret=created["signing_secret"],
        now=datetime.now(timezone.utc),
    )

    delivery_id = deliveries.json()["items"][0]["delivery_id"]
    detail = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            f"/webhook-deliveries/{delivery_id}"
        ),
        headers=admin_headers(),
    )

    assert detail.status_code == 200
    assert detail.json()["delivery"]["status"] == "DELIVERED"
    assert detail.json()["event"]["event_type"] == (
        "authorization.created"
    )
    assert len(detail.json()["attempts"]) == 1


def test_approval_workflow_emits_requested_and_resolved_events():
    provisioned = provision_project("Webhook Approval")
    project_id = provisioned["project"]["project_id"]
    api_key = provisioned["api_key"]
    create_subscription(
        project_id,
        ["approval.requested", "approval.resolved"],
    )
    authorize = test_client.post(
        "/v1/authorize",
        headers={"X-API-Key": api_key},
        json={
            "agent": "finance-agent",
            "action": "refund_payment",
            "context": {"amount": 750},
        },
    )
    decision_id = authorize.json()["decision_id"]
    resolution = test_client.post(
        f"/v1/approvals/{decision_id}/approve",
        headers={"X-API-Key": api_key},
        json={
            "resolved_by": "risk-reviewer",
            "reason": "Reviewed in ticket APR-7.",
        },
    )
    events = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-events"
        ),
        headers=admin_headers(),
    ).json()["items"]

    assert authorize.status_code == 200
    assert authorize.json()["decision"] == "REQUIRE_APPROVAL"
    assert resolution.status_code == 200
    assert {event["event_type"] for event in events} >= {
        "approval.requested",
        "approval.resolved",
    }


def test_administrative_policy_change_uses_transactional_outbox():
    provisioned = provision_project("Webhook Policy")
    project_id = provisioned["project"]["project_id"]
    create_subscription(project_id, ["policy.updated"])
    policy = next(
        policy
        for policy in load_policies(POLICIES_DIRECTORY)
        if policy.id == "refund-limit"
    ).model_dump(mode="json")
    policy["version"] = 2
    policy["conditions"][0]["value"] = 250

    response = test_client.put(
        (
            f"/v1/admin/projects/{project_id}"
            "/policies/refund-limit"
        ),
        headers=admin_headers(),
        json=policy,
    )
    events = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-events"
        ),
        headers=admin_headers(),
        params={"event_type": "policy.updated"},
    ).json()
    deliveries = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-deliveries"
        ),
        headers=admin_headers(),
    ).json()

    assert response.status_code == 200
    assert events["total"] == 1
    assert events["items"][0]["data"]["audit_event"][
        "action"
    ] == "POLICY_UPDATED"
    assert deliveries["total"] == 1


def test_webhook_resources_are_project_scoped_and_admin_only():
    first = provision_project("First Webhook Tenant")
    second = provision_project("Second Webhook Tenant")
    subscription = create_subscription(
        first["project"]["project_id"]
    )["subscription"]
    first_project_id = first["project"]["project_id"]
    second_project_id = second["project"]["project_id"]
    subscription_id = subscription["subscription_id"]

    no_admin = test_client.get(
        (
            f"/v1/admin/projects/{first_project_id}"
            "/webhook-subscriptions"
        )
    )
    cross_project = test_client.get(
        (
            f"/v1/admin/projects/{second_project_id}"
            f"/webhook-subscriptions/{subscription_id}"
        ),
        headers=admin_headers(),
    )
    missing = test_client.get(
        (
            f"/v1/admin/projects/{first_project_id}"
            f"/webhook-subscriptions/{uuid4()}"
        ),
        headers=admin_headers(),
    )

    assert no_admin.status_code == 401
    assert cross_project.status_code == 404
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == (
        "webhook_subscription_not_found"
    )


def test_webhook_api_validates_url_filters_and_pagination():
    project = provision_project("Webhook Validation")
    project_id = project["project"]["project_id"]
    invalid_url = test_client.post(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-subscriptions"
        ),
        headers=admin_headers(),
        json={"url": "http://127.0.0.1/internal"},
    )
    invalid_status = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-deliveries"
        ),
        headers=admin_headers(),
        params={"status": "BANANA"},
    )
    invalid_page = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/webhook-events"
        ),
        headers=admin_headers(),
        params={"limit": 101},
    )

    assert invalid_url.status_code == 422
    assert invalid_status.status_code == 422
    assert invalid_page.status_code == 422

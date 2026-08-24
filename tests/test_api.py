from fastapi.testclient import TestClient
import pytest

from app.authorization_models import AuthorizationResponse
from app.evidence_store import EvidenceStore
from app.main import app, get_evidence_store

from datetime import datetime
from uuid import UUID



client = TestClient(app)

@pytest.fixture(autouse=True)
def temporary_evidence_store(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    app.dependency_overrides[get_evidence_store] = lambda: store

    yield store

    app.dependency_overrides.clear()


def test_authorize_returns_deny_with_winning_policy():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "finance-agent",
            "action": "bank_transfer",
            "context": {
                "amount": 25000,
                "account_verified": False,
            },
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"] == "DENY"
    assert data["policy"] == "unverified-account"
    assert data["reason"] == (
        "Bank transfers from unverified accounts are denied."
    )
    assert data["evidence"] == {
        "field": "account_verified",
        "operator": "equals",
        "actual_value": False,
        "expected_value": False,
    }
    assert data["policy_version"] == 1


def test_authorize_returns_require_approval_with_winning_policy():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "finance-agent",
            "action": "bank_transfer",
            "context": {
                "amount": 25000,
                "account_verified": True,
            },
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"] == "REQUIRE_APPROVAL"
    assert data["policy"] == "large-transfer"
    assert data["reason"] == (
        "Bank transfers above 10000 require approval."
    )
    assert data["evidence"] == {
        "field": "amount",
        "operator": "greater_than",
        "actual_value": 25000,
        "expected_value": 10000,
    }
    assert data["policy_version"] == 1


def test_authorize_returns_allow_without_policy():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "support-agent",
            "action": "refund_payment",
            "context": {
                "amount": 300,
            },
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision"] == "ALLOW"
    assert data["policy"] is None
    assert data["reason"] == (
        "No policy required approval or denial."
    )
    assert data["evidence"] is None
    assert data["policy_version"] is None

def test_authorize_rejects_request_without_agent():
    response = client.post(
        "/v1/authorize",
        json={
            "action": "bank_transfer",
            "context": {
                "amount": 5000,
            },
        },
    )

    assert response.status_code == 422

    data = response.json()

    assert data["detail"]
    assert data["detail"][0]["loc"] == ["body", "agent"]


def test_authorize_rejects_non_object_context():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "finance-agent",
            "action": "bank_transfer",
            "context": ["invalid", "context"],
        },
    )

    assert response.status_code == 422

    data = response.json()

    assert any(
        error["loc"] == ["body", "context"]
        for error in data["detail"]
    )


def test_authorize_rejects_empty_agent():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "",
            "action": "bank_transfer",
            "context": {
                "amount": 5000,
            },
        },
    )

    assert response.status_code == 422


def test_authorize_rejects_blank_action():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "finance-agent",
            "action": "   ",
            "context": {
                "amount": 5000,
            },
        },
    )

    assert response.status_code == 422



def test_authorize_rejects_non_numeric_amount():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "finance-agent",
            "action": "bank_transfer",
            "context": {
                "amount": "a lot",
                "account_verified": True,
            },
        },
    )

    assert response.status_code == 422

    assert response.json()["detail"] == {
        "code": "invalid_policy_context",
        "message": (
            "Context field 'amount' is incompatible "
            "with operator 'greater_than'."
        ),
        "field": "amount",
        "operator": "greater_than",
    }


def test_authorize_rejects_boolean_field_with_string_value():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "finance-agent",
            "action": "bank_transfer",
            "context": {
                "amount": 5000,
                "account_verified": "false",
            },
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "invalid_policy_context",
        "message": (
            "Context field 'account_verified' is incompatible "
            "with operator 'equals'."
        ),
        "field": "account_verified",
        "operator": "equals",
    }


def test_authorize_returns_unique_decision_metadata():
    payload = {
        "agent": "support-agent",
        "action": "refund_payment",
        "context": {
            "amount": 300,
        },
    }

    first_response = client.post(
        "/v1/authorize",
        json=payload,
    )
    second_response = client.post(
        "/v1/authorize",
        json=payload,
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    first_data = first_response.json()
    second_data = second_response.json()

    UUID(first_data["decision_id"])
    UUID(second_data["decision_id"])

    assert first_data["decision_id"] != second_data["decision_id"]

    evaluated_at = datetime.fromisoformat(
        first_data["evaluated_at"].replace("Z", "+00:00")
    )

    assert evaluated_at.tzinfo is not None

def test_authorize_persists_decision(
    temporary_evidence_store,
):
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "finance-agent",
            "action": "bank_transfer",
            "context": {
                "amount": 5000,
                "account_verified": False,
            },
        },
    )

    assert response.status_code == 200

    returned_authorization = (
        AuthorizationResponse.model_validate(
            response.json()
        )
    )

    stored_authorization = temporary_evidence_store.get(
        returned_authorization.decision_id
    )

    assert stored_authorization == returned_authorization
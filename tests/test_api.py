from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


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
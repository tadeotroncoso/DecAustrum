from fastapi.testclient import TestClient
import pytest
import sqlite3
from app.bootstrap import bootstrap_default_project

from app.api_keys import (
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
)
from app.project_models import (
    DEFAULT_PROJECT_ID,
    Project,
)

from app.authorization_models import AuthorizationResponse
from app.evidence_store import EvidenceStore
from app.main import app, get_evidence_store
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies

from datetime import datetime, timezone
from uuid import UUID, uuid4

TEST_API_KEY = "test-api-key"
TEST_ADMIN_API_KEY = "test-admin-api-key"
TEST_EXECUTION_GRANT_SECRET = (
    "test-execution-grant-secret-at-least-32-bytes"
)

client = TestClient(
    app,
    headers={"X-API-Key": TEST_API_KEY},
)

unauthenticated_client = TestClient(app)

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
    monkeypatch.setenv(
        "DECAUSTRUM_EXECUTION_GRANT_SECRET",
        TEST_EXECUTION_GRANT_SECRET,
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


def provision_test_project(
    name: str = "Managed Project",
) -> dict:
    response = unauthenticated_client.post(
        "/v1/admin/projects",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
        json={"name": name},
    )

    assert response.status_code == 201

    return response.json()


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
        "match": "all",
        "conditions": [
            {
                "field": "account_verified",
                "operator": "equals",
                "actual_value": False,
                "expected_value": False,
                "matched": True,
            }
        ],
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
        "match": "all",
        "conditions": [
            {
                "field": "amount",
                "operator": "greater_than",
                "actual_value": 25000,
                "expected_value": 10000,
                "matched": True,
            }
        ],
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
        decision_id=returned_authorization.decision_id,
        project_id=returned_authorization.project_id,
    )
    assert stored_authorization == returned_authorization

def test_get_decision_returns_stored_authorization():
    create_response = client.post(
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

    assert create_response.status_code == 200

    created_data = create_response.json()
    decision_id = created_data["decision_id"]

    get_response = client.get(
        f"/v1/decisions/{decision_id}"
    )

    assert get_response.status_code == 200
    assert get_response.json() == created_data


def test_get_decision_returns_404_when_not_found():
    decision_id = uuid4()

    response = client.get(
        f"/v1/decisions/{decision_id}"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "decision_not_found",
        "message": (
            f"Decision '{decision_id}' was not found."
        ),
    }

def test_get_decision_rejects_invalid_uuid():
    response = client.get(
        "/v1/decisions/not-a-valid-uuid"
    )

    assert response.status_code == 422

def test_invalid_authorization_is_not_persisted(
    temporary_evidence_store,
):
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

    with sqlite3.connect(
        temporary_evidence_store.database_path
    ) as connection:
        stored_decisions = connection.execute(
            """
            SELECT COUNT(*)
            FROM authorization_decisions
            """
        ).fetchone()[0]

    assert stored_decisions == 0

def test_list_decisions_returns_empty_page():
    response = client.get("/v1/decisions")

    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "total": 0,
        "limit": 20,
        "offset": 0,
    }


def test_list_decisions_returns_paginated_results():
    for amount in (100, 200, 300):
        create_response = client.post(
            "/v1/authorize",
            json={
                "agent": "support-agent",
                "action": "refund_payment",
                "context": {
                    "amount": amount,
                },
            },
        )

        assert create_response.status_code == 200

    response = client.get(
        "/v1/decisions?limit=2&offset=1"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 3
    assert data["limit"] == 2
    assert data["offset"] == 1
    assert len(data["items"]) == 2

@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=101",
        "offset=-1",
    ],
)
def test_list_decisions_rejects_invalid_pagination(query):
    response = client.get(
        f"/v1/decisions?{query}"
    )

    assert response.status_code == 422

def test_require_approval_creates_pending_approval(
    temporary_evidence_store,
):
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

    authorization = AuthorizationResponse.model_validate(
        response.json()
    )

    approval = temporary_evidence_store.get_approval(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    )

    assert approval is not None
    assert approval.decision_id == authorization.decision_id
    assert approval.status == "PENDING"
    assert approval.requested_at == authorization.evaluated_at
    assert approval.expires_at is not None
    assert approval.expires_at > approval.requested_at
    assert approval.resolved_at is None
    assert approval.resolved_by is None

@pytest.mark.parametrize(
    ("payload", "expected_decision"),
    [
        (
            {
                "agent": "support-agent",
                "action": "refund_payment",
                "context": {
                    "amount": 300,
                },
            },
            "ALLOW",
        ),
        (
            {
                "agent": "finance-agent",
                "action": "bank_transfer",
                "context": {
                    "amount": 5000,
                    "account_verified": False,
                },
            },
            "DENY",
        ),
    ],
)
def test_non_approval_decisions_do_not_create_approval(
    payload,
    expected_decision,
    temporary_evidence_store,
):
    response = client.post(
        "/v1/authorize",
        json=payload,
    )

    assert response.status_code == 200

    authorization = AuthorizationResponse.model_validate(
        response.json()
    )

    assert authorization.decision == expected_decision

    approval = temporary_evidence_store.get_approval(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    )

    assert approval is None


def test_get_pending_approval():
    create_response = client.post(
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

    assert create_response.status_code == 200

    decision_id = create_response.json()["decision_id"]

    response = client.get(
        f"/v1/approvals/{decision_id}"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["decision_id"] == decision_id
    assert data["status"] == "PENDING"
    assert data["resolved_at"] is None
    assert data["resolved_by"] is None



def test_get_approval_returns_404_when_not_required():
    create_response = client.post(
        "/v1/authorize",
        json={
            "agent": "support-agent",
            "action": "refund_payment",
            "context": {
                "amount": 300,
            },
        },
    )

    decision_id = create_response.json()["decision_id"]

    response = client.get(
        f"/v1/approvals/{decision_id}"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "approval_not_found",
        "message": (
            f"Approval for decision "
            f"'{decision_id}' was not found."
        ),
    }


def test_get_approval_rejects_invalid_uuid():
    response = client.get(
        "/v1/approvals/not-a-valid-uuid"
    )

    assert response.status_code == 422

def create_pending_approval() -> str:
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
    assert response.json()["decision"] == "REQUIRE_APPROVAL"

    return response.json()["decision_id"]

def test_approve_pending_request():
    decision_id = create_pending_approval()

    response = client.post(
        f"/v1/approvals/{decision_id}/approve",
        json={
            "resolved_by": "security-admin",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "APPROVED"
    assert data["resolved_by"] == "security-admin"
    assert data["resolved_at"] is not None
    assert data["execution_grant"].startswith("rgt_exec_v1.")
    assert data["grant_id"]
    assert data["grant_expires_at"]


def test_reject_pending_request():
    decision_id = create_pending_approval()

    response = client.post(
        f"/v1/approvals/{decision_id}/reject",
        json={
            "resolved_by": "risk-admin",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert response.json()["resolved_by"] == "risk-admin"


def test_cannot_resolve_request_twice():
    decision_id = create_pending_approval()

    first_response = client.post(
        f"/v1/approvals/{decision_id}/approve",
        json={"resolved_by": "first-admin"},
    )

    second_response = client.post(
        f"/v1/approvals/{decision_id}/reject",
        json={"resolved_by": "second-admin"},
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 409

    detail = second_response.json()["detail"]

    assert detail["code"] == "approval_already_resolved"
    assert detail["current_status"] == "APPROVED"


def test_resolve_unknown_approval_returns_404():
    decision_id = uuid4()

    response = client.post(
        f"/v1/approvals/{decision_id}/approve",
        json={"resolved_by": "security-admin"},
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == (
        "approval_not_found"
    )


def test_resolution_rejects_blank_resolver():
    decision_id = create_pending_approval()

    response = client.post(
        f"/v1/approvals/{decision_id}/approve",
        json={"resolved_by": "   "},
    )

    assert response.status_code == 422


def test_list_approvals_returns_all_requests():
    create_pending_approval()
    create_pending_approval()

    response = client.get("/v1/approvals")

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 2
    assert len(data["items"]) == 2


def test_list_approvals_filters_by_status():
    approved_id = create_pending_approval()
    pending_id = create_pending_approval()

    approve_response = client.post(
        f"/v1/approvals/{approved_id}/approve",
        json={"resolved_by": "security-admin"},
    )

    assert approve_response.status_code == 200

    response = client.get(
        "/v1/approvals?status=PENDING"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == 1
    assert data["items"][0]["decision_id"] == pending_id
    assert data["items"][0]["status"] == "PENDING"


def test_list_approvals_rejects_unknown_status():
    response = client.get(
        "/v1/approvals?status=BANANA"
    )

    assert response.status_code == 422

def test_authorization_response_contains_policy_trace():
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

    trace_by_policy = {
        entry["policy_id"]: entry
        for entry in response.json()["trace"]
    }

    assert trace_by_policy["large-transfer"]["matched"] is True
    assert trace_by_policy["unverified-account"]["matched"] is True


def test_authorize_rejects_missing_api_key():
    response = unauthenticated_client.post(
        "/v1/authorize",
        json={
            "agent": "test-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {
        "code": "invalid_api_key",
        "message": "A valid API key is required.",
    }


def test_authorize_rejects_invalid_api_key():
    response = unauthenticated_client.post(
        "/v1/authorize",
        headers={"X-API-Key": "wrong-key"},
        json={
            "agent": "test-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert response.status_code == 401


def test_health_does_not_require_api_key():
    response = unauthenticated_client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_openapi_defines_api_key_security_scheme():
    schema = app.openapi()

    security_scheme = schema["components"]["securitySchemes"][
        "DecAustrumApiKey"
    ]

    assert security_scheme["type"] == "apiKey"
    assert security_scheme["in"] == "header"
    assert security_scheme["name"] == "X-API-Key"


def test_openapi_defines_admin_api_key_security_scheme():
    schema = app.openapi()

    security_scheme = schema["components"]["securitySchemes"][
        "DecAustrumAdminApiKey"
    ]

    assert security_scheme["type"] == "apiKey"
    assert security_scheme["in"] == "header"
    assert security_scheme["name"] == "X-Admin-API-Key"


def test_all_v1_endpoints_require_expected_api_key_in_openapi():
    schema = app.openapi()

    http_methods = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
    }

    for path, path_item in schema["paths"].items():
        if not path.startswith("/v1/"):
            continue

        for method in http_methods:
            operation = path_item.get(method)

            if operation is None:
                continue

            expected_scheme = (
                "DecAustrumAdminApiKey"
                if path.startswith("/v1/admin/")
                else "DecAustrumApiKey"
            )

            assert {expected_scheme: []} in operation.get(
                "security",
                [],
            ), f"{method.upper()} {path} is not protected"


def test_project_api_key_cannot_provision_project():
    response = client.post(
        "/v1/admin/projects",
        json={"name": "Unauthorized Project"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {
        "code": "invalid_admin_api_key",
        "message": (
            "A valid admin API key is required."
        ),
    }


def test_invalid_admin_api_key_cannot_provision_project():
    response = unauthenticated_client.post(
        "/v1/admin/projects",
        headers={"X-Admin-API-Key": "wrong-key"},
        json={"name": "Unauthorized Project"},
    )

    assert response.status_code == 401


def test_admin_can_provision_project(
    temporary_evidence_store,
):
    response = unauthenticated_client.post(
        "/v1/admin/projects",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
        json={"name": "  Acme Production  "},
    )

    assert response.status_code == 201

    data = response.json()
    project_data = data["project"]
    issued_api_key = data["api_key"]
    project_id = UUID(project_data["project_id"])

    assert project_data["name"] == "Acme Production"
    assert project_data["status"] == "ACTIVE"
    assert issued_api_key.startswith("rtk_")

    stored_project = temporary_evidence_store.get_project(
        project_id
    )

    assert stored_project is not None
    assert stored_project.name == "Acme Production"

    with sqlite3.connect(
        temporary_evidence_store.database_path
    ) as connection:
        connection.row_factory = sqlite3.Row
        stored_key = connection.execute(
            """
            SELECT key_prefix, key_hash
            FROM project_api_keys
            WHERE project_id = ?
            """,
            (str(project_id),),
        ).fetchone()

    assert stored_key is not None
    assert stored_key["key_prefix"] == (
        get_api_key_prefix(issued_api_key)
    )
    assert stored_key["key_hash"] == (
        hash_api_key(issued_api_key)
    )
    assert stored_key["key_hash"] != issued_api_key

    authorization_response = unauthenticated_client.post(
        "/v1/authorize",
        headers={"X-API-Key": issued_api_key},
        json={
            "agent": "provisioned-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert authorization_response.status_code == 200
    assert authorization_response.json()["project_id"] == (
        str(project_id)
    )


def test_project_provisioning_rejects_blank_name():
    response = unauthenticated_client.post(
        "/v1/admin/projects",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
        json={"name": "   "},
    )

    assert response.status_code == 422


def test_admin_can_create_additional_project_api_key():
    provisioned = provision_test_project()
    project_id = provisioned["project"]["project_id"]

    response = unauthenticated_client.post(
        f"/v1/admin/projects/{project_id}/api-keys",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    assert response.status_code == 201

    data = response.json()
    issued_api_key = data["api_key"]
    metadata = data["key"]

    assert issued_api_key.startswith("rtk_")
    assert issued_api_key != provisioned["api_key"]
    assert metadata["project_id"] == project_id
    assert metadata["key_prefix"] == (
        get_api_key_prefix(issued_api_key)
    )
    assert metadata["revoked_at"] is None
    assert "key_hash" not in metadata

    authorization_response = unauthenticated_client.post(
        "/v1/authorize",
        headers={"X-API-Key": issued_api_key},
        json={
            "agent": "rotated-key-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert authorization_response.status_code == 200
    assert authorization_response.json()["project_id"] == (
        project_id
    )


def test_admin_lists_paginated_api_key_metadata():
    provisioned = provision_test_project()
    project_id = provisioned["project"]["project_id"]

    additional_response = unauthenticated_client.post(
        f"/v1/admin/projects/{project_id}/api-keys",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    assert additional_response.status_code == 201

    first_page = unauthenticated_client.get(
        (
            f"/v1/admin/projects/{project_id}/api-keys"
            "?limit=1&offset=0"
        ),
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    second_page = unauthenticated_client.get(
        (
            f"/v1/admin/projects/{project_id}/api-keys"
            "?limit=1&offset=1"
        ),
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    assert first_page.status_code == 200
    assert second_page.status_code == 200
    assert first_page.json()["total"] == 2
    assert second_page.json()["total"] == 2
    assert len(first_page.json()["items"]) == 1
    assert len(second_page.json()["items"]) == 1

    listed_items = (
        first_page.json()["items"]
        + second_page.json()["items"]
    )

    expected_fields = {
        "api_key_id",
        "project_id",
        "key_prefix",
        "created_at",
        "revoked_at",
    }

    assert all(
        set(item) == expected_fields
        for item in listed_items
    )

    listed_prefixes = {
        item["key_prefix"]
        for item in listed_items
    }

    assert listed_prefixes == {
        get_api_key_prefix(provisioned["api_key"]),
        get_api_key_prefix(
            additional_response.json()["api_key"]
        ),
    }


def test_admin_revokes_project_api_key_idempotently():
    provisioned = provision_test_project()
    project_id = provisioned["project"]["project_id"]
    issued_api_key = provisioned["api_key"]

    list_response = unauthenticated_client.get(
        f"/v1/admin/projects/{project_id}/api-keys",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    api_key_id = list_response.json()["items"][0][
        "api_key_id"
    ]

    path = (
        f"/v1/admin/projects/{project_id}"
        f"/api-keys/{api_key_id}"
    )

    first_response = unauthenticated_client.delete(
        path,
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    second_response = unauthenticated_client.delete(
        path,
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert first_response.json()["revoked_at"] is not None
    assert second_response.json()["revoked_at"] == (
        first_response.json()["revoked_at"]
    )

    authorization_response = unauthenticated_client.post(
        "/v1/authorize",
        headers={"X-API-Key": issued_api_key},
        json={
            "agent": "revoked-key-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert authorization_response.status_code == 401


def test_admin_cannot_revoke_key_from_another_project():
    first = provision_test_project("First Project")
    second = provision_test_project("Second Project")

    first_project_id = first["project"]["project_id"]
    second_project_id = second["project"]["project_id"]

    list_response = unauthenticated_client.get(
        (
            f"/v1/admin/projects/{first_project_id}"
            "/api-keys"
        ),
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    first_api_key_id = list_response.json()["items"][0][
        "api_key_id"
    ]

    response = unauthenticated_client.delete(
        (
            f"/v1/admin/projects/{second_project_id}"
            f"/api-keys/{first_api_key_id}"
        ),
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == (
        "api_key_not_found"
    )

    authorization_response = unauthenticated_client.post(
        "/v1/authorize",
        headers={"X-API-Key": first["api_key"]},
        json={
            "agent": "still-active-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert authorization_response.status_code == 200


def test_api_key_lifecycle_rejects_unknown_resources():
    provisioned = provision_test_project()
    project_id = provisioned["project"]["project_id"]
    unknown_project_id = uuid4()
    unknown_api_key_id = uuid4()

    unknown_project_response = unauthenticated_client.get(
        (
            f"/v1/admin/projects/{unknown_project_id}"
            "/api-keys"
        ),
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    unknown_key_response = unauthenticated_client.delete(
        (
            f"/v1/admin/projects/{project_id}"
            f"/api-keys/{unknown_api_key_id}"
        ),
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    assert unknown_project_response.status_code == 404
    assert unknown_project_response.json()["detail"]["code"] == (
        "project_not_found"
    )

    assert unknown_key_response.status_code == 404
    assert unknown_key_response.json()["detail"]["code"] == (
        "api_key_not_found"
    )


def test_disabled_project_cannot_receive_new_api_key(
    temporary_evidence_store,
):
    provisioned = provision_test_project()
    project_id = provisioned["project"]["project_id"]

    with sqlite3.connect(
        temporary_evidence_store.database_path
    ) as connection:
        connection.execute(
            """
            UPDATE projects
            SET status = 'DISABLED'
            WHERE project_id = ?
            """,
            (project_id,),
        )

    response = unauthenticated_client.post(
        f"/v1/admin/projects/{project_id}/api-keys",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == (
        "project_disabled"
    )

def test_authorize_replays_same_idempotent_request():
    payload = {
        "agent": "finance-agent",
        "action": "refund_payment",
        "context": {
            "amount": 750,
        },
    }

    headers = {
        "Idempotency-Key": "refund-request-123",
    }

    first_response = client.post(
        "/v1/authorize",
        headers=headers,
        json=payload,
    )

    second_response = client.post(
        "/v1/authorize",
        headers=headers,
        json=payload,
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200
    assert second_response.json() == first_response.json()

    decisions_response = client.get("/v1/decisions")
    approvals_response = client.get("/v1/approvals")

    assert decisions_response.json()["total"] == 1
    assert approvals_response.json()["total"] == 1


def test_authorize_rejects_reused_key_for_different_request():
    headers = {
        "Idempotency-Key": "conflicting-request",
    }

    first_response = client.post(
        "/v1/authorize",
        headers=headers,
        json={
            "agent": "finance-agent",
            "action": "refund_payment",
            "context": {
                "amount": 750,
            },
        },
    )

    second_response = client.post(
        "/v1/authorize",
        headers=headers,
        json={
            "agent": "finance-agent",
            "action": "refund_payment",
            "context": {
                "amount": 751,
            },
        },
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 409
    assert second_response.json()["detail"] == {
        "code": "idempotency_key_conflict",
        "message": (
            "Idempotency key has already been used "
            "with a different request."
        ),
    }

def test_authorize_recovers_from_idempotency_race(
    temporary_evidence_store,
    monkeypatch,
):
    store = temporary_evidence_store

    payload = {
        "agent": "finance-agent",
        "action": "refund_payment",
        "context": {
            "amount": 750,
        },
    }

    headers = {
        "Idempotency-Key": "concurrent-request",
    }

    original_response = client.post(
        "/v1/authorize",
        headers=headers,
        json=payload,
    )

    original_get = store.get_idempotency_record
    lookup_count = 0

    def miss_first_lookup(
        project_id: UUID,
        idempotency_key: str,
    ):
        nonlocal lookup_count
        lookup_count += 1

        if lookup_count == 1:
            return None

        return original_get(
            project_id=project_id,
            idempotency_key=idempotency_key,
        )

    monkeypatch.setattr(
        store,
        "get_idempotency_record",
        miss_first_lookup,
    )

    replayed_response = client.post(
        "/v1/authorize",
        headers=headers,
        json=payload,
    )

    assert original_response.status_code == 200
    assert replayed_response.status_code == 200
    assert replayed_response.json() == (
        original_response.json()
    )
    assert lookup_count == 2

    decisions_response = client.get("/v1/decisions")
    approvals_response = client.get("/v1/approvals")

    assert decisions_response.json()["total"] == 1
    assert approvals_response.json()["total"] == 1


def test_list_policies_returns_active_catalog():
    response = client.get("/v1/policies")

    assert response.status_code == 200

    data = response.json()

    assert data["total"] == len(data["items"])

    policy_ids = {
        policy["id"]
        for policy in data["items"]
    }

    assert "refund-limit" in policy_ids
    assert "large-transfer" in policy_ids
    assert "unverified-account" in policy_ids


def test_get_policy_returns_active_policy():
    response = client.get(
        "/v1/policies/refund-limit"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == "refund-limit"
    assert data["action"] == "refund_payment"
    assert data["decision"] == "REQUIRE_APPROVAL"
    assert data["version"] == 1
    assert data["match"] == "all"
    assert len(data["conditions"]) >= 1


def test_get_policy_returns_404_when_not_found():
    response = client.get(
        "/v1/policies/missing-policy"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "policy_not_found",
        "message": (
            "Policy 'missing-policy' was not found."
        ),
    }

def test_disabled_project_api_key_is_rejected(
    temporary_evidence_store,
):
    store = temporary_evidence_store

    with sqlite3.connect(
        store.database_path
    ) as connection:
        connection.execute(
            """
            UPDATE projects
            SET status = 'DISABLED'
            """
        )

    response = client.get("/v1/policies")

    assert response.status_code == 401
    assert response.json()["detail"] == {
        "code": "invalid_api_key",
        "message": "A valid API key is required.",
    }

def test_authorize_returns_authenticated_project_id():
    response = client.post(
        "/v1/authorize",
        json={
            "agent": "test-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert response.status_code == 200
    assert response.json()["project_id"] == str(
        DEFAULT_PROJECT_ID
    )

def test_decisions_are_isolated_between_projects(
    temporary_evidence_store,
):
    store = temporary_evidence_store
    created_at = datetime.now(timezone.utc)

    second_project = Project(
        project_id=uuid4(),
        name="Second Project",
        status="ACTIVE",
        created_at=created_at,
    )

    second_secret = generate_project_api_key()

    second_api_key = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=second_project.project_id,
        key_prefix=get_api_key_prefix(second_secret),
        key_hash=hash_api_key(second_secret),
        created_at=created_at,
    )

    store.save_project_with_api_key(
        project=second_project,
        api_key=second_api_key,
        policies=load_policies(POLICIES_DIRECTORY),
    )

    second_response = unauthenticated_client.post(
        "/v1/authorize",
        headers={"X-API-Key": second_secret},
        json={
            "agent": "second-agent",
            "action": "send_email",
            "context": {},
        },
    )

    assert second_response.status_code == 200
    assert second_response.json()["project_id"] == str(
        second_project.project_id
    )

    decision_id = second_response.json()["decision_id"]

    default_project_response = client.get(
        f"/v1/decisions/{decision_id}"
    )

    assert default_project_response.status_code == 404

    default_project_list = client.get(
        "/v1/decisions"
    )

    assert default_project_list.status_code == 200
    assert default_project_list.json()["total"] == 0

def test_approval_endpoints_are_isolated_between_projects(
    temporary_evidence_store,
):
    store = temporary_evidence_store
    created_at = datetime.now(timezone.utc)

    second_project = Project(
        project_id=uuid4(),
        name="Second Project",
        status="ACTIVE",
        created_at=created_at,
    )

    second_secret = generate_project_api_key()

    second_api_key = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=second_project.project_id,
        key_prefix=get_api_key_prefix(second_secret),
        key_hash=hash_api_key(second_secret),
        created_at=created_at,
    )

    store.save_project_with_api_key(
        project=second_project,
        api_key=second_api_key,
        policies=load_policies(POLICIES_DIRECTORY),
    )

    create_response = unauthenticated_client.post(
        "/v1/authorize",
        headers={"X-API-Key": second_secret},
        json={
            "agent": "second-finance-agent",
            "action": "bank_transfer",
            "context": {
                "amount": 25000,
                "account_verified": True,
            },
        },
    )

    assert create_response.status_code == 200
    assert (
        create_response.json()["decision"]
        == "REQUIRE_APPROVAL"
    )

    decision_id = create_response.json()["decision_id"]

    cross_project_get = client.get(
        f"/v1/approvals/{decision_id}"
    )

    assert cross_project_get.status_code == 404

    cross_project_list = client.get("/v1/approvals")

    assert cross_project_list.status_code == 200
    assert cross_project_list.json()["total"] == 0

    cross_project_resolution = client.post(
        f"/v1/approvals/{decision_id}/approve",
        json={"resolved_by": "wrong-project-admin"},
    )

    assert cross_project_resolution.status_code == 404

def test_idempotency_keys_are_scoped_to_project(
    temporary_evidence_store,
):
    store = temporary_evidence_store
    created_at = datetime.now(timezone.utc)

    second_project = Project(
        project_id=uuid4(),
        name="Second Project",
        status="ACTIVE",
        created_at=created_at,
    )

    second_secret = generate_project_api_key()

    second_api_key = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=second_project.project_id,
        key_prefix=get_api_key_prefix(second_secret),
        key_hash=hash_api_key(second_secret),
        created_at=created_at,
    )

    store.save_project_with_api_key(
        project=second_project,
        api_key=second_api_key,
        policies=load_policies(POLICIES_DIRECTORY),
    )

    first_response = client.post(
        "/v1/authorize",
        headers={
            "Idempotency-Key": "shared-key",
        },
        json={
            "agent": "first-agent",
            "action": "send_email",
            "context": {
                "recipient": "first@example.com",
            },
        },
    )

    assert first_response.status_code == 200

    second_response = unauthenticated_client.post(
        "/v1/authorize",
        headers={
            "X-API-Key": second_secret,
            "Idempotency-Key": "shared-key",
        },
        json={
            "agent": "second-agent",
            "action": "send_email",
            "context": {
                "recipient": "second@example.com",
            },
        },
    )

    assert second_response.status_code == 200
    assert second_response.json()["project_id"] == str(
        second_project.project_id
    )
    assert (
        second_response.json()["decision_id"]
        != first_response.json()["decision_id"]
    )

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import app.evidence_store as evidence_store_module
import app.services.execution_grants as execution_service
from app.bootstrap import bootstrap_default_project
from app.evidence_store import EvidenceStore
from app.execution_grants import (
    hash_execution_grant_token,
    parse_execution_grant_token,
)
from app.main import app, get_evidence_store
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID


TEST_API_KEY = "execution-grant-project-key"
TEST_ADMIN_API_KEY = "execution-grant-admin-key"
TEST_SECRET = "execution-grant-api-secret-at-least-32-bytes"
AUTHORIZATION_REQUEST = {
    "agent": "finance-agent",
    "action": "bank_transfer",
    "context": {
        "amount": 25_000,
        "account_verified": True,
    },
}

client = TestClient(
    app,
    headers={"X-API-Key": TEST_API_KEY},
)


@pytest.fixture(autouse=True)
def temporary_store(tmp_path, monkeypatch):
    monkeypatch.setenv("REGTRACE_API_KEY", TEST_API_KEY)
    monkeypatch.setenv(
        "REGTRACE_ADMIN_API_KEY",
        TEST_ADMIN_API_KEY,
    )
    monkeypatch.setenv(
        "REGTRACE_EXECUTION_GRANT_SECRET",
        TEST_SECRET,
    )
    store = EvidenceStore(tmp_path / "regtrace.db")
    store.initialize()
    bootstrap_default_project(store=store, api_key=TEST_API_KEY)
    store.seed_project_policies(
        project_id=DEFAULT_PROJECT_ID,
        policies=load_policies(POLICIES_DIRECTORY),
        seeded_at=datetime.now(timezone.utc),
    )
    app.dependency_overrides[get_evidence_store] = lambda: store

    yield store

    app.dependency_overrides.clear()


def authorize_and_approve() -> tuple[dict, dict]:
    authorization = client.post(
        "/v1/authorize",
        json=AUTHORIZATION_REQUEST,
    )
    assert authorization.status_code == 200
    assert authorization.json()["decision"] == "REQUIRE_APPROVAL"

    approval = client.post(
        (
            "/v1/approvals/"
            f"{authorization.json()['decision_id']}/approve"
        ),
        json={
            "resolved_by": "security-reviewer",
            "reason": "Reviewed transfer evidence.",
        },
    )
    assert approval.status_code == 200
    return authorization.json(), approval.json()


def consumption_payload(token: str) -> dict:
    return {
        "execution_grant": token,
        **AUTHORIZATION_REQUEST,
        "consumed_by": "finance-runtime",
    }


def test_approval_issues_persisted_signed_grant_without_plaintext(
    temporary_store,
):
    authorization, approval = authorize_and_approve()
    token = approval["execution_grant"]
    parsed = parse_execution_grant_token(token, TEST_SECRET)

    assert approval["decision_id"] == authorization["decision_id"]
    assert approval["status"] == "APPROVED"
    assert token.startswith("rgt_exec_v1.")
    assert str(parsed.grant_id) == approval["grant_id"]
    assert str(parsed.decision_id) == authorization["decision_id"]
    assert parsed.project_id == DEFAULT_PROJECT_ID

    with sqlite3.connect(
        temporary_store.database_path
    ) as connection:
        row = connection.execute(
            """
            SELECT token_hash, request_fingerprint
            FROM execution_grants
            WHERE grant_id = ?
            """,
            (approval["grant_id"],),
        ).fetchone()

    assert row is not None
    assert row[0] == hash_execution_grant_token(token)
    assert token not in str(row)


def test_execution_grant_is_consumed_exactly_once():
    authorization, approval = authorize_and_approve()
    body = consumption_payload(approval["execution_grant"])

    first = client.post(
        "/v1/execution-grants/consume",
        json=body,
    )
    replay = client.post(
        "/v1/execution-grants/consume",
        json=body,
    )

    assert first.status_code == 200
    assert first.json()["authorized"] is True
    assert first.json()["decision_id"] == authorization["decision_id"]
    assert first.json()["grant_id"] == approval["grant_id"]
    assert replay.status_code == 409
    assert replay.json()["detail"]["code"] == (
        "execution_grant_already_consumed"
    )


def test_concurrent_consumption_authorizes_only_one_request():
    _, approval = authorize_and_approve()
    body = consumption_payload(approval["execution_grant"])

    def consume():
        return TestClient(app).post(
            "/v1/execution-grants/consume",
            headers={"X-API-Key": TEST_API_KEY},
            json=body,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: consume(), range(2)))

    assert sorted(response.status_code for response in responses) == [
        200,
        409,
    ]
    conflict = next(
        response for response in responses if response.status_code == 409
    )
    assert conflict.json()["detail"]["code"] == (
        "execution_grant_already_consumed"
    )


def test_execution_grant_rejects_changed_request_without_consuming():
    _, approval = authorize_and_approve()
    changed = consumption_payload(approval["execution_grant"])
    changed["context"] = {
        "amount": 30_000,
        "account_verified": True,
    }

    mismatch = client.post(
        "/v1/execution-grants/consume",
        json=changed,
    )
    valid = client.post(
        "/v1/execution-grants/consume",
        json=consumption_payload(approval["execution_grant"]),
    )

    assert mismatch.status_code == 409
    assert mismatch.json()["detail"]["code"] == (
        "execution_grant_mismatch"
    )
    assert valid.status_code == 200


def test_tampered_execution_grant_is_rejected_generically():
    _, approval = authorize_and_approve()
    token = approval["execution_grant"]
    middle = len(token) // 2
    replacement = "A" if token[middle] != "A" else "B"
    tampered = token[:middle] + replacement + token[middle + 1 :]

    response = client.post(
        "/v1/execution-grants/consume",
        json=consumption_payload(tampered),
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {
        "code": "invalid_execution_grant",
        "message": "Execution grant is invalid.",
    }


def test_validation_error_does_not_echo_execution_grant():
    _, approval = authorize_and_approve()
    token = approval["execution_grant"]
    body = consumption_payload(token)
    body["consumed_by"] = "   "

    response = client.post(
        "/v1/execution-grants/consume",
        json=body,
    )

    assert response.status_code == 422
    assert token not in response.text


def test_execution_grant_is_project_scoped():
    _, approval = authorize_and_approve()
    provisioned = TestClient(app).post(
        "/v1/admin/projects",
        headers={
            "X-Admin-API-Key": TEST_ADMIN_API_KEY,
            "X-Admin-Actor": "provisioner",
        },
        json={"name": "Other Project"},
    )
    assert provisioned.status_code == 201

    response = TestClient(app).post(
        "/v1/execution-grants/consume",
        headers={"X-API-Key": provisioned.json()["api_key"]},
        json=consumption_payload(approval["execution_grant"]),
    )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == (
        "invalid_execution_grant"
    )


def test_approve_retry_returns_same_active_grant():
    authorization, first = authorize_and_approve()

    second = client.post(
        (
            "/v1/approvals/"
            f"{authorization['decision_id']}/approve"
        ),
        json={"resolved_by": "security-reviewer"},
    )

    assert second.status_code == 200
    assert second.json()["grant_id"] == first["grant_id"]
    assert second.json()["execution_grant"] == first["execution_grant"]


def test_concurrent_approval_returns_one_idempotent_grant():
    authorization = client.post(
        "/v1/authorize",
        json=AUTHORIZATION_REQUEST,
    ).json()
    url = f"/v1/approvals/{authorization['decision_id']}/approve"

    def approve():
        return TestClient(app).post(
            url,
            headers={"X-API-Key": TEST_API_KEY},
            json={"resolved_by": "security-reviewer"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: approve(), range(2)))

    assert [response.status_code for response in responses] == [200, 200]
    assert len(
        {response.json()["grant_id"] for response in responses}
    ) == 1
    assert len(
        {
            response.json()["execution_grant"]
            for response in responses
        }
    ) == 1


def test_concurrent_approve_and_reject_have_one_terminal_winner():
    authorization = client.post(
        "/v1/authorize",
        json=AUTHORIZATION_REQUEST,
    ).json()
    base_url = f"/v1/approvals/{authorization['decision_id']}"

    def resolve(path: str):
        return TestClient(app).post(
            base_url + path,
            headers={"X-API-Key": TEST_API_KEY},
            json={"resolved_by": "security-reviewer"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        approve_future = executor.submit(resolve, "/approve")
        reject_future = executor.submit(resolve, "/reject")
        responses = [approve_future.result(), reject_future.result()]

    assert sorted(response.status_code for response in responses) == [
        200,
        409,
    ]
    current = client.get(base_url)
    assert current.status_code == 200
    assert current.json()["status"] in {"APPROVED", "REJECTED"}


def test_expired_grant_is_persisted_and_cannot_execute(
    temporary_store,
    monkeypatch,
):
    _, approval = authorize_and_approve()
    token = approval["execution_grant"]
    payload = parse_execution_grant_token(token, TEST_SECRET)
    future = payload.expires_at + timedelta(seconds=1)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return future.replace(tzinfo=None)
            return future.astimezone(tz)

    monkeypatch.setattr(
        execution_service,
        "datetime",
        FutureDateTime,
    )
    response = client.post(
        "/v1/execution-grants/consume",
        json=consumption_payload(token),
    )
    grant = temporary_store.get_execution_grant(
        grant_id=payload.grant_id,
        project_id=DEFAULT_PROJECT_ID,
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == (
        "execution_grant_expired"
    )
    assert grant is not None
    assert grant.status == "EXPIRED"


def test_expired_pending_approval_cannot_issue_grant(
    temporary_store,
    monkeypatch,
):
    authorization = client.post(
        "/v1/authorize",
        json=AUTHORIZATION_REQUEST,
    ).json()
    approval = temporary_store.approvals.get(
        decision_id=authorization["decision_id"],
        project_id=DEFAULT_PROJECT_ID,
    )
    assert approval is not None
    future = approval.expires_at + timedelta(seconds=1)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            if tz is None:
                return future.replace(tzinfo=None)
            return future.astimezone(tz)

    monkeypatch.setattr(
        evidence_store_module,
        "datetime",
        FutureDateTime,
    )
    read = client.get(
        f"/v1/approvals/{authorization['decision_id']}"
    )
    approve = client.post(
        f"/v1/approvals/{authorization['decision_id']}/approve",
        json={"resolved_by": "late-reviewer"},
    )

    assert read.status_code == 200
    assert read.json()["status"] == "EXPIRED"
    assert approve.status_code == 409
    assert approve.json()["detail"]["code"] == "approval_expired"
    assert temporary_store.get_execution_grant_for_decision(
        decision_id=authorization["decision_id"],
        project_id=DEFAULT_PROJECT_ID,
    ) is None


def test_rejected_approval_never_issues_execution_grant(
    temporary_store,
):
    authorization = client.post(
        "/v1/authorize",
        json=AUTHORIZATION_REQUEST,
    ).json()
    rejected = client.post(
        f"/v1/approvals/{authorization['decision_id']}/reject",
        json={"resolved_by": "risk-reviewer"},
    )
    approve = client.post(
        f"/v1/approvals/{authorization['decision_id']}/approve",
        json={"resolved_by": "security-reviewer"},
    )

    assert rejected.status_code == 200
    assert rejected.json()["status"] == "REJECTED"
    assert approve.status_code == 409
    assert temporary_store.get_execution_grant_for_decision(
        decision_id=authorization["decision_id"],
        project_id=DEFAULT_PROJECT_ID,
    ) is None


def test_grant_lifecycle_is_audited_and_webhooked_without_token(
    temporary_store,
):
    _, approval = authorize_and_approve()
    token = approval["execution_grant"]
    consumed = client.post(
        "/v1/execution-grants/consume",
        json=consumption_payload(token),
    )
    assert consumed.status_code == 200

    audit_events = temporary_store.list_administrative_audit_events(
        project_id=DEFAULT_PROJECT_ID,
        resource_id=approval["grant_id"],
        limit=20,
    )
    webhook_events = temporary_store.list_webhook_events(
        project_id=DEFAULT_PROJECT_ID,
        limit=100,
    )
    grant_event_types = {
        event.event_type
        for event in webhook_events
        if event.resource_id == approval["grant_id"]
    }
    serialized = json.dumps(
        {
            "audit": [
                event.model_dump(mode="json")
                for event in audit_events
            ],
            "webhooks": [
                event.model_dump(mode="json")
                for event in webhook_events
            ],
        },
        sort_keys=True,
    )

    assert {event.action for event in audit_events} == {
        "EXECUTION_GRANT_ISSUED",
        "EXECUTION_GRANT_CONSUMED",
    }
    assert grant_event_types == {
        "execution_grant.issued",
        "execution_grant.consumed",
    }
    assert token not in serialized
    assert hash_execution_grant_token(token) not in serialized

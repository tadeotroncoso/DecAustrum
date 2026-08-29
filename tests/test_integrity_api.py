import hashlib
import json
import sqlite3
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


def project_headers(api_key: str = TEST_API_KEY) -> dict[str, str]:
    return {"X-API-Key": api_key}


def admin_headers() -> dict[str, str]:
    return {"X-Admin-API-Key": TEST_ADMIN_API_KEY}


def authorize(
    *,
    api_key: str = TEST_API_KEY,
    ticket_id: int = 42,
    idempotency_key: str | None = None,
):
    headers = project_headers(api_key)

    if idempotency_key is not None:
        headers["Idempotency-Key"] = idempotency_key

    return test_client.post(
        "/v1/authorize",
        headers=headers,
        json={
            "agent": "support-agent",
            "action": "read_ticket",
            "context": {"ticket_id": ticket_id},
        },
    )


def provision_project(name: str) -> dict:
    response = test_client.post(
        "/v1/admin/projects",
        headers=admin_headers(),
        json={"name": name},
    )

    assert response.status_code == 201

    return response.json()


def test_api_exposes_proofs_ledger_and_verification():
    first = authorize(ticket_id=41)
    second = authorize(ticket_id=42)

    assert first.status_code == 200
    assert second.status_code == 200

    first_decision_id = first.json()["decision_id"]
    second_decision_id = second.json()["decision_id"]

    first_proof_response = test_client.get(
        f"/v1/decisions/{first_decision_id}/integrity",
        headers=project_headers(),
    )
    second_proof_response = test_client.get(
        f"/v1/decisions/{second_decision_id}/integrity",
        headers=project_headers(),
    )
    ledger_response = test_client.get(
        "/v1/integrity",
        headers=project_headers(),
    )
    verification_response = test_client.get(
        "/v1/integrity/verify",
        headers=project_headers(),
    )

    assert first_proof_response.status_code == 200
    assert second_proof_response.status_code == 200
    first_proof = first_proof_response.json()
    second_proof = second_proof_response.json()
    assert first_proof["sequence_number"] == 1
    assert first_proof["previous_hash"] is None
    assert first_proof["algorithm"] == "SHA-256"
    assert first_proof["schema_version"] == 1
    assert len(first_proof["payload_hash"]) == 64
    assert len(first_proof["record_hash"]) == 64
    assert second_proof["sequence_number"] == 2
    assert second_proof["previous_hash"] == (
        first_proof["record_hash"]
    )

    assert ledger_response.status_code == 200
    ledger = ledger_response.json()
    assert ledger["total"] == 2
    assert [
        item["decision_id"]
        for item in ledger["items"]
    ] == [second_decision_id, first_decision_id]

    assert verification_response.status_code == 200
    verification = verification_response.json()
    assert verification["verified"] is True
    assert verification["total_decisions"] == 2
    assert verification["checked_records"] == 2
    assert verification["head_hash"] == (
        second_proof["record_hash"]
    )
    assert verification["failure"] is None


def test_api_exports_self_contained_verifiable_decision():
    authorization = authorize(ticket_id=84).json()
    decision_id = authorization["decision_id"]

    response = test_client.get(
        f"/v1/decisions/{decision_id}/evidence",
        headers=project_headers(),
    )

    assert response.status_code == 200
    bundle = response.json()
    assert bundle["decision"] == authorization
    assert bundle["integrity"]["decision_id"] == decision_id
    integrity = bundle["integrity"]
    payload_v1_fields = (
        "decision_id",
        "project_id",
        "evaluated_at",
        "decision",
        "policy",
        "policy_version",
        "reason",
        "evidence",
        "agent",
        "action",
        "context",
        "trace",
    )
    payload_v1 = {
        field: bundle["decision"][field]
        for field in payload_v1_fields
    }
    externally_calculated_payload_hash = hashlib.sha256(
        json.dumps(
            payload_v1,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    assert integrity["payload_hash"] == (
        externally_calculated_payload_hash
    )

    record_envelope = {
        "algorithm": integrity["algorithm"],
        "created_at": bundle["decision"]["evaluated_at"],
        "decision_id": decision_id,
        "payload_hash": integrity["payload_hash"],
        "previous_hash": integrity["previous_hash"],
        "project_id": bundle["decision"]["project_id"],
        "schema_version": integrity["schema_version"],
        "sequence_number": integrity["sequence_number"],
    }
    externally_calculated_hash = hashlib.sha256(
        json.dumps(
            record_envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    assert integrity["record_hash"] == externally_calculated_hash


def test_verification_api_accepts_external_head_checkpoint():
    authorize(ticket_id=84)
    initial = test_client.get(
        "/v1/integrity/verify",
        headers=project_headers(),
    )
    trusted_head = initial.json()["head_hash"]

    authorize(ticket_id=85)

    matching = test_client.get(
        "/v1/integrity/verify",
        headers=project_headers(),
        params={"expected_head_hash": trusted_head},
    )
    mismatching = test_client.get(
        "/v1/integrity/verify",
        headers=project_headers(),
        params={"expected_head_hash": "0" * 64},
    )
    invalid = test_client.get(
        "/v1/integrity/verify",
        headers=project_headers(),
        params={"expected_head_hash": "not-a-sha256-digest"},
    )

    assert matching.status_code == 200
    assert matching.json()["verified"] is True
    assert matching.json()["head_hash"] != trusted_head
    assert mismatching.status_code == 200
    assert mismatching.json()["verified"] is False
    assert mismatching.json()["head_hash"] == (
        matching.json()["head_hash"]
    )
    assert mismatching.json()["failure"] == {
        "code": "head_hash_mismatch",
        "message": (
            "Expected chain checkpoint is not present in the "
            "current chain."
        ),
        "decision_id": None,
        "sequence_number": None,
        "expected": "0" * 64,
        "actual": matching.json()["head_hash"],
    }
    assert invalid.status_code == 422


def test_empty_project_has_valid_empty_chain():
    provisioned = provision_project("Empty Integrity Chain")

    response = test_client.get(
        "/v1/integrity/verify",
        headers=project_headers(provisioned["api_key"]),
    )

    assert response.status_code == 200
    assert response.json()["verified"] is True
    assert response.json()["total_decisions"] == 0
    assert response.json()["checked_records"] == 0
    assert response.json()["head_hash"] is None


def test_integrity_endpoints_are_isolated_by_project():
    first = provision_project("First Integrity Project")
    second = provision_project("Second Integrity Project")
    first_decision = authorize(
        api_key=first["api_key"],
        ticket_id=1,
    ).json()
    authorize(
        api_key=second["api_key"],
        ticket_id=2,
    )

    hidden_proof = test_client.get(
        (
            f"/v1/decisions/{first_decision['decision_id']}"
            "/integrity"
        ),
        headers=project_headers(second["api_key"]),
    )
    second_ledger = test_client.get(
        "/v1/integrity",
        headers=project_headers(second["api_key"]),
    )

    assert hidden_proof.status_code == 404
    assert hidden_proof.json()["detail"]["code"] == (
        "decision_integrity_not_found"
    )
    assert second_ledger.status_code == 200
    assert second_ledger.json()["total"] == 1
    assert second_ledger.json()["items"][0][
        "project_id"
    ] == second["project"]["project_id"]


def test_unknown_integrity_proof_returns_specific_error():
    decision_id = uuid4()

    response = test_client.get(
        f"/v1/decisions/{decision_id}/integrity",
        headers=project_headers(),
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {
        "code": "decision_integrity_not_found",
        "message": (
            f"Integrity proof for decision '{decision_id}' "
            "was not found."
        ),
    }


def test_integrity_ledger_validates_pagination():
    authorize(ticket_id=1)
    authorize(ticket_id=2)
    authorize(ticket_id=3)

    page = test_client.get(
        "/v1/integrity?limit=1&offset=1",
        headers=project_headers(),
    )
    invalid_limit = test_client.get(
        "/v1/integrity?limit=0",
        headers=project_headers(),
    )
    invalid_offset = test_client.get(
        "/v1/integrity?offset=-1",
        headers=project_headers(),
    )

    assert page.status_code == 200
    assert page.json()["total"] == 3
    assert page.json()["limit"] == 1
    assert page.json()["offset"] == 1
    assert page.json()["items"][0]["sequence_number"] == 2
    assert invalid_limit.status_code == 422
    assert invalid_offset.status_code == 422


def test_idempotent_retry_does_not_append_duplicate_proof():
    first = authorize(
        ticket_id=42,
        idempotency_key="same-authorization",
    )
    second = authorize(
        ticket_id=42,
        idempotency_key="same-authorization",
    )
    ledger = test_client.get(
        "/v1/integrity",
        headers=project_headers(),
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == first.json()
    assert ledger.json()["total"] == 1
    assert ledger.json()["items"][0]["decision_id"] == (
        first.json()["decision_id"]
    )


def test_verification_api_reports_tampered_payload(
    temporary_evidence_store,
):
    decision = authorize(ticket_id=42).json()

    with sqlite3.connect(
        temporary_evidence_store.database_path
    ) as connection:
        connection.execute(
            "DROP TRIGGER prevent_authorization_decision_update"
        )
        connection.execute(
            """
            UPDATE authorization_decisions
            SET context_json = '{"ticket_id": 999}'
            WHERE decision_id = ?
            """,
            (decision["decision_id"],),
        )

    response = test_client.get(
        "/v1/integrity/verify",
        headers=project_headers(),
    )

    assert response.status_code == 200
    verification = response.json()
    assert verification["verified"] is False
    assert verification["head_hash"] is None
    assert verification["failure"]["code"] == (
        "payload_hash_mismatch"
    )
    assert verification["failure"]["decision_id"] == (
        decision["decision_id"]
    )


def test_admin_can_verify_managed_project_integrity():
    provisioned = provision_project("Admin Verification")
    project_id = provisioned["project"]["project_id"]
    authorize(api_key=provisioned["api_key"])

    response = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/integrity/verify"
        ),
        headers=admin_headers(),
    )
    unknown_project = test_client.get(
        (
            f"/v1/admin/projects/{uuid4()}"
            "/integrity/verify"
        ),
        headers=admin_headers(),
    )
    tenant_attempt = test_client.get(
        (
            f"/v1/admin/projects/{project_id}"
            "/integrity/verify"
        ),
        headers=project_headers(provisioned["api_key"]),
    )

    assert response.status_code == 200
    assert response.json()["verified"] is True
    assert response.json()["total_decisions"] == 1
    assert unknown_project.status_code == 404
    assert unknown_project.json()["detail"]["code"] == (
        "project_not_found"
    )
    assert tenant_attempt.status_code == 401


@pytest.mark.parametrize(
    "path",
    [
        "/v1/integrity",
        "/v1/integrity/verify",
        f"/v1/decisions/{uuid4()}/integrity",
        f"/v1/decisions/{uuid4()}/evidence",
    ],
)
def test_integrity_endpoints_require_project_api_key(path):
    response = test_client.get(path)

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == (
        "invalid_api_key"
    )

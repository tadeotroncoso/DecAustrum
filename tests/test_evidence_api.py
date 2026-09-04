import csv
import io
import json
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import app.services.evidence as evidence_service
from app.api_keys import generate_project_api_key
from app.bootstrap import bootstrap_default_project
from app.evidence import (
    load_evidence_bundle_archive,
    verify_evidence_bundle,
)
from app.evidence_store import EvidenceStore
from app.main import app, get_evidence_store
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID

TEST_API_KEY = generate_project_api_key()
TEST_ADMIN_API_KEY = "evidence-test-admin-api-key"

client = TestClient(app)


@pytest.fixture(autouse=True)
def temporary_store(tmp_path, monkeypatch):
    monkeypatch.setenv("DECAUSTRUM_API_KEY", TEST_API_KEY)
    monkeypatch.setenv(
        "DECAUSTRUM_ADMIN_API_KEY",
        TEST_ADMIN_API_KEY,
    )
    store = EvidenceStore(tmp_path / "test.db")
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


def project_headers(api_key: str = TEST_API_KEY):
    return {"X-API-Key": api_key}


def admin_headers():
    return {"X-Admin-API-Key": TEST_ADMIN_API_KEY}


def authorize(
    *,
    agent: str = "support-agent",
    action: str = "read_ticket",
    context: dict | None = None,
    api_key: str = TEST_API_KEY,
):
    return client.post(
        "/v1/authorize",
        headers=project_headers(api_key),
        json={
            "agent": agent,
            "action": action,
            "context": context or {"ticket_id": 42},
        },
    )


def test_decision_api_supports_combined_search_and_pagination():
    allowed = authorize()
    pending = authorize(
        agent="finance-agent",
        action="bank_transfer",
        context={
            "amount": 25_000,
            "account_verified": True,
        },
    )
    denied = authorize(
        agent="finance-agent",
        action="bank_transfer",
        context={
            "amount": 5_000,
            "account_verified": False,
        },
    )

    assert allowed.status_code == 200
    assert pending.status_code == 200
    assert denied.status_code == 200

    response = client.get(
        "/v1/decisions",
        headers=project_headers(),
        params={
            "decision": "REQUIRE_APPROVAL",
            "agent": "finance-agent",
            "action": "bank_transfer",
            "has_policy": "true",
            "approval_status": "PENDING",
            "query": "approval",
            "sort": "asc",
            "limit": 1,
            "offset": 0,
        },
    )

    assert response.status_code == 200
    page = response.json()
    assert page["total"] == 1
    assert page["items"] == [pending.json()]


def test_decision_api_rejects_invalid_filter_combinations():
    incompatible = client.get(
        "/v1/decisions",
        headers=project_headers(),
        params={
            "policy_id": "refund-limit",
            "has_policy": "false",
        },
    )
    naive_time = client.get(
        "/v1/decisions",
        headers=project_headers(),
        params={"evaluated_after": "2026-08-29T10:00:00"},
    )

    assert incompatible.status_code == 422
    assert incompatible.json()["detail"]["code"] == (
        "invalid_decision_search_filters"
    )
    assert naive_time.status_code == 422


def test_api_streams_json_ndjson_and_csv_evidence_exports():
    authorization = authorize().json()

    json_response = client.get(
        "/v1/evidence/export",
        headers=project_headers(),
        params={"format": "json", "action": "read_ticket"},
    )
    ndjson_response = client.get(
        "/v1/evidence/export",
        headers=project_headers(),
        params={"format": "ndjson", "action": "read_ticket"},
    )
    csv_response = client.get(
        "/v1/evidence/export",
        headers=project_headers(),
        params={"format": "csv", "action": "read_ticket"},
    )

    assert json_response.status_code == 200
    assert json_response.headers["content-type"].startswith(
        "application/json"
    )
    assert json_response.headers["x-decaustrum-record-count"] == "1"
    assert json_response.json()["records"][0]["decision"] == (
        authorization
    )

    assert ndjson_response.status_code == 200
    ndjson_records = [
        json.loads(line)
        for line in ndjson_response.text.splitlines()
    ]
    assert ndjson_records[0]["decision"] == authorization

    assert csv_response.status_code == 200
    csv_records = list(csv.DictReader(io.StringIO(csv_response.text)))
    assert csv_records[0]["decision_id"] == (
        authorization["decision_id"]
    )
    assert csv_records[0]["record_hash"] == (
        ndjson_records[0]["integrity"]["record_hash"]
    )


def test_api_builds_offline_verifiable_filtered_bundle():
    first = authorize(context={"ticket_id": 1}).json()
    authorize(
        action="send_email",
        context={"recipient": "audit@example.com"},
    )
    first_proof = client.get(
        f"/v1/decisions/{first['decision_id']}/integrity",
        headers=project_headers(),
    ).json()

    response = client.get(
        "/v1/evidence/bundle",
        headers=project_headers(),
        params={
            "action": "read_ticket",
            "expected_head_hash": first_proof["record_hash"],
        },
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert len(response.headers["x-decaustrum-bundle-sha256"]) == 64
    bundle = load_evidence_bundle_archive(response.content)
    verification = verify_evidence_bundle(
        bundle,
        expected_head_hash=first_proof["record_hash"],
    )
    assert len(bundle.records) == 1
    assert len(bundle.chain) == 2
    assert bundle.manifest.criteria.action == "read_ticket"
    assert verification.verified is True


def test_exports_require_project_authentication():
    export_response = client.get("/v1/evidence/export")
    bundle_response = client.get("/v1/evidence/bundle")

    assert export_response.status_code == 401
    assert bundle_response.status_code == 401


def test_admin_search_and_export_remain_project_scoped():
    provisioned = client.post(
        "/v1/admin/projects",
        headers=admin_headers(),
        json={"name": "Evidence Tenant"},
    ).json()
    project_id = provisioned["project"]["project_id"]
    api_key = provisioned["api_key"]
    second_authorization = authorize(
        agent="tenant-agent",
        api_key=api_key,
    ).json()
    authorize(agent="default-agent")

    search = client.get(
        f"/v1/admin/projects/{project_id}/decisions",
        headers=admin_headers(),
    )
    export = client.get(
        f"/v1/admin/projects/{project_id}/evidence/export",
        headers=admin_headers(),
        params={"format": "ndjson"},
    )

    assert search.status_code == 200
    assert search.json()["items"] == [second_authorization]
    assert export.status_code == 200
    exported = json.loads(export.text)
    assert exported["decision"]["project_id"] == project_id
    assert exported["decision"]["agent"] == "tenant-agent"


def test_admin_evidence_endpoints_enforce_auth_and_project_existence():
    project_id = uuid4()

    unauthorized = client.get(
        f"/v1/admin/projects/{project_id}/evidence/export"
    )
    missing = client.get(
        f"/v1/admin/projects/{project_id}/evidence/export",
        headers=admin_headers(),
    )

    assert unauthorized.status_code == 401
    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "project_not_found"


def test_export_rejects_untrusted_checkpoint():
    authorize()

    response = client.get(
        "/v1/evidence/bundle",
        headers=project_headers(),
        params={"expected_head_hash": "0" * 64},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == (
        "evidence_integrity_verification_failed"
    )


def test_export_refuses_a_tampered_decision_ledger(
    temporary_store,
):
    authorize()

    with sqlite3.connect(temporary_store.database_path) as connection:
        connection.execute(
            "DROP TRIGGER prevent_authorization_decision_update"
        )
        connection.execute(
            """
            UPDATE authorization_decisions
            SET reason = 'tampered'
            WHERE project_id = ?
            """,
            (str(DEFAULT_PROJECT_ID),),
        )

    response = client.get(
        "/v1/evidence/export",
        headers=project_headers(),
    )

    assert response.status_code == 409
    assert response.json()["detail"]["verification"][
        "verified"
    ] is False


def test_export_applies_a_bounded_record_limit(monkeypatch):
    authorize()
    monkeypatch.setattr(
        evidence_service,
        "MAX_EVIDENCE_EXPORT_RECORDS",
        0,
    )

    response = client.get(
        "/v1/evidence/export",
        headers=project_headers(),
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == (
        "evidence_export_too_large"
    )


def test_export_applies_a_bounded_serialized_size(monkeypatch):
    authorize()
    monkeypatch.setattr(
        evidence_service,
        "MAX_EVIDENCE_EXPORT_BYTES",
        1,
    )

    response = client.get(
        "/v1/evidence/export",
        headers=project_headers(),
    )

    assert response.status_code == 413
    assert response.json()["detail"] == {
        "code": "evidence_export_too_large",
        "message": "The selected evidence exceeds the export byte limit.",
        "maximum_bytes": 1,
    }


def test_bundle_applies_a_bounded_chain_size(monkeypatch):
    authorize()
    monkeypatch.setattr(
        evidence_service,
        "MAX_EVIDENCE_BUNDLE_CHAIN_BYTES",
        1,
    )

    response = client.get(
        "/v1/evidence/bundle",
        headers=project_headers(),
    )

    assert response.status_code == 413
    assert response.json()["detail"] == {
        "code": "evidence_chain_too_large",
        "message": (
            "The integrity chain exceeds the generated evidence byte "
            "limit."
        ),
        "maximum_bytes": 1,
    }


def test_bundle_applies_a_bounded_archive_size(monkeypatch):
    authorize()
    monkeypatch.setattr(
        evidence_service,
        "MAX_EVIDENCE_BUNDLE_BYTES",
        1,
    )

    response = client.get(
        "/v1/evidence/bundle",
        headers=project_headers(),
    )

    assert response.status_code == 413
    assert response.json()["detail"] == {
        "code": "evidence_bundle_too_large",
        "message": (
            "The generated evidence bundle exceeds its byte limit."
        ),
        "maximum_bytes": 1,
    }

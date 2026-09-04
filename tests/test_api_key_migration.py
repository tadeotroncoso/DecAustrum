"""Breaking pre-release credential migration; only temporary test stores."""

import sqlite3
from datetime import datetime, timezone
from unittest.mock import Mock
from uuid import uuid4

import pytest

from app.api_keys import (
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
    verify_api_key,
)
from app.audit import SYSTEM_BOOTSTRAP_AUDIT_CONTEXT
from app.authorization_models import AuthorizationResponse
from app.bootstrap import bootstrap_default_project
from app.evidence_store import EvidenceStore
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import Project


def test_legacy_rows_are_retired_without_deleting_projects(tmp_path):
    store = EvidenceStore(tmp_path / "migration.db")
    store.initialize()
    project = Project(
        project_id=uuid4(), name="Preserved project", status="ACTIVE",
        created_at=datetime.now(timezone.utc),
    )
    store.save_project(project)
    decision = AuthorizationResponse(
        decision_id=uuid4(), project_id=project.project_id,
        evaluated_at=project.created_at, decision="DENY", policy=None,
        policy_version=None, reason="Preserved test evidence", evidence=None,
        agent="test-agent", action="test-action", context={}, trace=[],
    )
    store.save(decision)
    store.seed_project_policies(
        project.project_id, load_policies(POLICIES_DIRECTORY), project.created_at,
        audit_context=SYSTEM_BOOTSTRAP_AUDIT_CONTEXT,
    )
    with store.database.connect() as connection:
        history_before = connection.execute(
            "SELECT * FROM administrative_audit_events ORDER BY rowid"
        ).fetchall()
        policies_before = connection.execute(
            "SELECT * FROM project_policies ORDER BY rowid"
        ).fetchall()
        integrity_before = connection.execute(
            "SELECT * FROM decision_integrity_records ORDER BY rowid"
        ).fetchall()
    active_id, revoked_id = uuid4(), uuid4()
    previous_revocation = "2026-08-01T00:00:00+00:00"
    # Synthetic old digests, not real credentials or a runtime legacy hash path.
    with store.database.connect() as connection:
        connection.execute("DROP INDEX IF EXISTS idx_project_api_key_selector")
        for key_id, digest, role, revoked in (
            (active_id, "a" * 64, "RUNTIME", None),
            (revoked_id, "b" * 64, "REVIEWER", previous_revocation),
        ):
            connection.execute(
                "INSERT INTO project_api_keys VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(key_id), str(project.project_id), "old-prefix", digest,
                 role, project.created_at.isoformat(), revoked),
            )

    store.initialize()
    with store.database.connect() as connection:
        migrated = connection.execute(
            "SELECT api_key_id, key_prefix, key_hash, role, revoked_at "
            "FROM project_api_keys ORDER BY role"
        ).fetchall()
    assert len(migrated) == 2
    for key_id, prefix, verifier, _, revoked in migrated:
        assert prefix == f"retired_{key_id}"
        assert verifier == f"retired${key_id}"
        assert revoked is not None
    assert dict((row[0], row[4]) for row in migrated)[str(revoked_id)] == (
        previous_revocation
    )
    assert store.get_project(project.project_id) == project
    assert store.get(decision.decision_id, project.project_id) == decision
    with store.database.connect() as connection:
        assert connection.execute(
            "SELECT * FROM administrative_audit_events ORDER BY rowid"
        ).fetchall() == history_before
        assert connection.execute(
            "SELECT * FROM project_policies ORDER BY rowid"
        ).fetchall() == policies_before
        assert connection.execute(
            "SELECT * FROM decision_integrity_records ORDER BY rowid"
        ).fetchall() == integrity_before
    assert store.count_project_api_keys(project.project_id) == 2
    assert {key.role for key in store.list_project_api_keys(project.project_id)} == {
        "RUNTIME", "REVIEWER"
    }
    store.initialize()
    with store.database.connect() as connection:
        assert connection.execute(
            "SELECT api_key_id, key_prefix, key_hash, role, revoked_at "
            "FROM project_api_keys ORDER BY role"
        ).fetchall() == migrated


def test_new_key_survives_restart_but_verifier_cannot_authenticate(tmp_path):
    store = EvidenceStore(tmp_path / "current.db")
    store.initialize()
    credential = generate_project_api_key()
    project = bootstrap_default_project(store, credential)
    with store.database.connect() as connection:
        verifier = connection.execute(
            "SELECT key_hash FROM project_api_keys"
        ).fetchone()[0]
    assert verify_api_key(credential, verifier)
    assert store.get_active_api_key_principal(verifier) is None
    store.initialize()
    assert store.get_active_project_by_api_key(credential) == project


def test_public_selector_is_not_an_authenticator(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "selector.db")
    store.initialize()
    credential = generate_project_api_key()
    bootstrap_default_project(store, credential)
    selector = get_api_key_prefix(credential)
    assert store.get_active_api_key_principal(selector) is None
    wrong_secret = generate_project_api_key().split(".")[1]
    assert store.get_active_api_key_principal(f"{selector}.{wrong_secret}") is None

    verifier = Mock(side_effect=AssertionError("KDF must not run"))
    monkeypatch.setattr("app.storage.api_keys.verify_api_key", verifier)
    for invalid in ("", "legacy-token", "x" * 100_000, generate_project_api_key()):
        assert store.get_active_api_key_principal(invalid) is None
    verifier.assert_not_called()


def test_selector_cannot_be_reused_even_after_revocation(tmp_path):
    store = EvidenceStore(tmp_path / "unique.db")
    store.initialize()
    credential = generate_project_api_key()
    project = bootstrap_default_project(store, credential)
    principal = store.get_active_api_key_principal(credential)
    assert principal is not None
    store.revoke_project_api_key(
        project.project_id, principal.api_key_id, datetime.now(timezone.utc)
    )
    other = get_api_key_prefix(credential) + "." + "A" * 43
    with pytest.raises(sqlite3.IntegrityError):
        store.save_project_api_key(ProjectApiKeyRecord(
            api_key_id=uuid4(), project_id=project.project_id,
            key_prefix=get_api_key_prefix(other), key_hash=hash_api_key(other),
            created_at=datetime.now(timezone.utc),
        ))
    assert store.get_active_api_key_principal(credential) is None


def test_revocation_during_verification_is_respected(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "race.db")
    store.initialize()
    credential = generate_project_api_key()
    project = bootstrap_default_project(store, credential)
    principal = store.get_active_api_key_principal(credential)
    assert principal is not None

    def revoke_then_verify(presented, verifier):
        store.revoke_project_api_key(
            project.project_id, principal.api_key_id, datetime.now(timezone.utc)
        )
        return verify_api_key(presented, verifier)

    monkeypatch.setattr("app.storage.api_keys.verify_api_key", revoke_then_verify)
    assert store.get_active_api_key_principal(credential) is None

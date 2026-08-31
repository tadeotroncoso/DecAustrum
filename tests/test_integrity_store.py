import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from app.approval_models import ApprovalRecord
from app.authorization_models import AuthorizationResponse
from app.evidence_store import EvidenceStore
from app.exceptions import DecisionIntegrityMigrationError
from app.idempotency import IdempotencyRecord
from app.integrity import calculate_authorization_payload_hash
from app.storage.database import CREATE_DECISIONS_TABLE
from app.storage.decisions import (
    AuthorizationDecisionRepository,
)

EVALUATED_AT = datetime(
    2026,
    8,
    29,
    12,
    0,
    tzinfo=timezone.utc,
)


def build_authorization(
    *,
    project_id: UUID | None = None,
    evaluated_at: datetime = EVALUATED_AT,
    decision: str = "ALLOW",
) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision_id=uuid4(),
        project_id=project_id or uuid4(),
        evaluated_at=evaluated_at,
        decision=decision,
        policy=None,
        policy_version=None,
        reason="No policy required approval or denial.",
        evidence=None,
        trace=[],
        agent="support-agent",
        action="read_ticket",
        context={"ticket_id": 42},
    )


def test_initialize_creates_immutable_integrity_schema(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(decision_integrity_records)"
        ).fetchall()
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(decision_integrity_records)"
        ).fetchall()
        indexes = connection.execute(
            "PRAGMA index_list(decision_integrity_records)"
        ).fetchall()
        triggers = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'trigger'
            AND tbl_name IN (
                'authorization_decisions',
                'decision_integrity_records'
            )
            """
        ).fetchall()

    assert {
        column[1]
        for column in columns
    } == {
        "decision_id",
        "project_id",
        "sequence_number",
        "previous_hash",
        "payload_hash",
        "record_hash",
        "algorithm",
        "schema_version",
        "created_at",
    }
    assert {
        column[1]
        for column in columns
        if column[5] > 0
    } == {"decision_id"}
    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == "authorization_decisions"
    assert {
        index[1]
        for index in indexes
    } >= {"idx_decision_integrity_project_chain"}
    assert {
        trigger[0]
        for trigger in triggers
    } == {
        "prevent_authorization_decision_update",
        "prevent_authorization_decision_delete",
        "enforce_decision_integrity_project",
        "prevent_decision_integrity_update",
        "prevent_decision_integrity_delete",
    }


def test_initialize_adds_schema_version_to_legacy_integrity_table(
    tmp_path,
):
    database_path = tmp_path / "legacy-integrity.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute(CREATE_DECISIONS_TABLE)
        connection.execute(
            """
            CREATE TABLE decision_integrity_records (
                decision_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                previous_hash TEXT,
                payload_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE,
                algorithm TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (project_id, sequence_number),
                FOREIGN KEY (decision_id)
                    REFERENCES authorization_decisions(decision_id)
            )
            """
        )

    store = EvidenceStore(database_path)
    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(decision_integrity_records)"
        ).fetchall()

    assert "schema_version" in {
        column[1]
        for column in columns
    }


def test_integrity_record_must_match_decision_project(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    authorization = build_authorization()

    with store.database.connect() as connection:
        AuthorizationDecisionRepository.insert(
            connection,
            authorization,
        )

        with pytest.raises(
            sqlite3.IntegrityError,
            match=(
                "integrity project must match decision project"
            ),
        ):
            connection.execute(
                """
                INSERT INTO decision_integrity_records (
                    decision_id,
                    project_id,
                    sequence_number,
                    previous_hash,
                    payload_hash,
                    record_hash,
                    algorithm,
                    schema_version,
                    created_at
                )
                VALUES (?, ?, 1, NULL, ?, ?, 'SHA-256', 1, ?)
                """,
                (
                    str(authorization.decision_id),
                    str(uuid4()),
                    "0" * 64,
                    "1" * 64,
                    authorization.evaluated_at.isoformat(),
                ),
            )


def test_saved_decisions_form_verifiable_project_chain(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project_id = uuid4()
    first = build_authorization(project_id=project_id)
    second = build_authorization(
        project_id=project_id,
        evaluated_at=EVALUATED_AT + timedelta(seconds=1),
    )

    store.save(first)
    store.save(second)

    first_proof = store.get_decision_integrity(
        decision_id=first.decision_id,
        project_id=project_id,
    )
    second_proof = store.get_decision_integrity(
        decision_id=second.decision_id,
        project_id=project_id,
    )
    verification = store.verify_decision_integrity(project_id)

    assert first_proof is not None
    assert second_proof is not None
    assert first_proof.sequence_number == 1
    assert first_proof.schema_version == 1
    assert first_proof.previous_hash is None
    assert first_proof.payload_hash == (
        calculate_authorization_payload_hash(first)
    )
    assert second_proof.sequence_number == 2
    assert second_proof.previous_hash == first_proof.record_hash
    assert verification.verified is True
    assert verification.total_decisions == 2
    assert verification.checked_records == 2
    assert verification.head_hash == second_proof.record_hash
    assert verification.failure is None
    assert [
        proof.decision_id
        for proof in store.list_decision_integrity_records(
            project_id=project_id,
        )
    ] == [second.decision_id, first.decision_id]


def test_verification_compares_trusted_chain_head(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    authorization = build_authorization()
    store.save(authorization)
    proof = store.get_decision_integrity(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    )

    assert proof is not None

    later_authorization = build_authorization(
        project_id=authorization.project_id,
        evaluated_at=EVALUATED_AT + timedelta(seconds=1),
    )
    store.save(later_authorization)
    later_proof = store.get_decision_integrity(
        decision_id=later_authorization.decision_id,
        project_id=authorization.project_id,
    )

    assert later_proof is not None

    matching = store.verify_decision_integrity(
        project_id=authorization.project_id,
        expected_head_hash=proof.record_hash,
    )
    mismatching = store.verify_decision_integrity(
        project_id=authorization.project_id,
        expected_head_hash="0" * 64,
    )

    assert matching.verified is True
    assert matching.head_hash == later_proof.record_hash
    assert mismatching.verified is False
    assert mismatching.checked_records == 2
    assert mismatching.head_hash == later_proof.record_hash
    assert mismatching.failure is not None
    assert mismatching.failure.code == "head_hash_mismatch"
    assert mismatching.failure.expected == "0" * 64
    assert mismatching.failure.actual == later_proof.record_hash


def test_integrity_chains_are_isolated_by_project(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    first_project_id = uuid4()
    second_project_id = uuid4()
    first = build_authorization(project_id=first_project_id)
    second = build_authorization(project_id=second_project_id)

    store.save(first)
    store.save(second)

    first_proof = store.get_decision_integrity(
        decision_id=first.decision_id,
        project_id=first_project_id,
    )
    second_proof = store.get_decision_integrity(
        decision_id=second.decision_id,
        project_id=second_project_id,
    )

    assert first_proof is not None
    assert second_proof is not None
    assert first_proof.sequence_number == 1
    assert second_proof.sequence_number == 1
    assert first_proof.previous_hash is None
    assert second_proof.previous_hash is None
    assert store.get_decision_integrity(
        decision_id=first.decision_id,
        project_id=second_project_id,
    ) is None
    assert store.verify_decision_integrity(
        first_project_id
    ).verified is True
    assert store.verify_decision_integrity(
        second_project_id
    ).verified is True


def test_integrity_failure_rolls_back_complete_authorization(
    tmp_path,
    monkeypatch,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    authorization = build_authorization(
        decision="REQUIRE_APPROVAL"
    )
    approval = ApprovalRecord(
        decision_id=authorization.decision_id,
        status="PENDING",
        requested_at=authorization.evaluated_at,
    )
    idempotency = IdempotencyRecord(
        project_id=authorization.project_id,
        idempotency_key="integrity-rollback",
        request_fingerprint="request-fingerprint",
        decision_id=authorization.decision_id,
        created_at=authorization.evaluated_at,
    )

    def fail_integrity_insert(*_):
        raise sqlite3.IntegrityError(
            "simulated integrity failure"
        )

    monkeypatch.setattr(
        store.integrity,
        "insert",
        fail_integrity_insert,
    )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="simulated integrity failure",
    ):
        store.save_authorization_with_approval(
            authorization=authorization,
            approval=approval,
            idempotency_record=idempotency,
        )

    assert store.get(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    ) is None
    assert store.get_approval(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    ) is None
    assert store.get_idempotency_record(
        project_id=authorization.project_id,
        idempotency_key=idempotency.idempotency_key,
    ) is None
    assert store.count_decision_integrity_records(
        authorization.project_id
    ) == 0


def test_initialize_backfills_existing_decisions_once(
    tmp_path,
):
    database_path = tmp_path / "legacy.db"
    project_id = uuid4()
    first = build_authorization(project_id=project_id)
    second = build_authorization(
        project_id=project_id,
        evaluated_at=EVALUATED_AT + timedelta(seconds=1),
    )

    with sqlite3.connect(database_path) as connection:
        connection.execute(CREATE_DECISIONS_TABLE)
        AuthorizationDecisionRepository.insert(connection, first)
        AuthorizationDecisionRepository.insert(connection, second)

    store = EvidenceStore(database_path)
    store.initialize()
    store.initialize()

    proofs = store.list_decision_integrity_records(project_id)

    assert [proof.sequence_number for proof in proofs] == [2, 1]
    assert proofs[0].previous_hash == proofs[1].record_hash
    assert store.count_decision_integrity_records(project_id) == 2
    assert store.verify_decision_integrity(
        project_id
    ).verified is True


def test_initialize_rejects_partial_integrity_migration(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project_id = uuid4()
    store.save(build_authorization(project_id=project_id))
    store.save(
        build_authorization(
            project_id=project_id,
            evaluated_at=EVALUATED_AT + timedelta(seconds=1),
        )
    )

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "DROP TRIGGER prevent_decision_integrity_delete"
        )
        connection.execute(
            """
            DELETE FROM decision_integrity_records
            WHERE project_id = ?
            AND sequence_number = 2
            """,
            (str(project_id),),
        )

    with pytest.raises(
        DecisionIntegrityMigrationError
    ) as exc_info:
        store.initialize()

    assert exc_info.value.project_id == project_id
    assert exc_info.value.decision_count == 2
    assert exc_info.value.integrity_count == 1


def test_decisions_and_integrity_records_are_immutable(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    authorization = build_authorization()
    store.save(authorization)

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="authorization decisions are immutable",
        ):
            connection.execute(
                """
                UPDATE authorization_decisions
                SET reason = 'changed'
                WHERE decision_id = ?
                """,
                (str(authorization.decision_id),),
            )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="authorization decisions are immutable",
        ):
            connection.execute(
                """
                DELETE FROM authorization_decisions
                WHERE decision_id = ?
                """,
                (str(authorization.decision_id),),
            )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="integrity records are immutable",
        ):
            connection.execute(
                """
                UPDATE decision_integrity_records
                SET record_hash = ?
                WHERE decision_id = ?
                """,
                (
                    "0" * 64,
                    str(authorization.decision_id),
                ),
            )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="integrity records are immutable",
        ):
            connection.execute(
                """
                DELETE FROM decision_integrity_records
                WHERE decision_id = ?
                """,
                (str(authorization.decision_id),),
            )

    assert store.verify_decision_integrity(
        authorization.project_id
    ).verified is True


@pytest.mark.parametrize(
    ("tamper_kind", "expected_code", "checked_records"),
    [
        ("payload", "payload_hash_mismatch", 0),
        ("unreadable_payload", "payload_unreadable", 0),
        ("previous_hash", "previous_hash_mismatch", 1),
        ("record_hash", "record_hash_mismatch", 1),
        ("sequence", "sequence_mismatch", 1),
        ("created_at", "created_at_mismatch", 1),
        ("missing_record", "record_count_mismatch", 0),
    ],
)
def test_verification_reports_first_tampered_record(
    tmp_path,
    tamper_kind,
    expected_code,
    checked_records,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project_id = uuid4()
    first = build_authorization(project_id=project_id)
    second = build_authorization(
        project_id=project_id,
        evaluated_at=EVALUATED_AT + timedelta(seconds=1),
    )
    store.save(first)
    store.save(second)

    with sqlite3.connect(store.database_path) as connection:
        if tamper_kind in {"payload", "unreadable_payload"}:
            connection.execute(
                "DROP TRIGGER prevent_authorization_decision_update"
            )
            context_json = (
                '{"ticket_id":999}'
                if tamper_kind == "payload"
                else "{broken-json"
            )
            connection.execute(
                """
                UPDATE authorization_decisions
                SET context_json = ?
                WHERE decision_id = ?
                """,
                (
                    context_json,
                    str(first.decision_id),
                ),
            )
        elif tamper_kind == "missing_record":
            connection.execute(
                "DROP TRIGGER prevent_decision_integrity_delete"
            )
            connection.execute(
                """
                DELETE FROM decision_integrity_records
                WHERE decision_id = ?
                """,
                (str(second.decision_id),),
            )
        else:
            connection.execute(
                "DROP TRIGGER prevent_decision_integrity_update"
            )

            if tamper_kind == "previous_hash":
                column = "previous_hash"
                value = "0" * 64
            elif tamper_kind == "record_hash":
                column = "record_hash"
                value = "0" * 64
            elif tamper_kind == "sequence":
                column = "sequence_number"
                value = 3
            else:
                column = "created_at"
                value = "2000-01-01T00:00:00+00:00"

            connection.execute(
                f"""
                UPDATE decision_integrity_records
                SET {column} = ?
                WHERE decision_id = ?
                """,
                (
                    value,
                    str(second.decision_id),
                ),
            )

    verification = store.verify_decision_integrity(project_id)

    assert verification.verified is False
    assert verification.checked_records == checked_records
    assert verification.head_hash is None
    assert verification.failure is not None
    assert verification.failure.code == expected_code

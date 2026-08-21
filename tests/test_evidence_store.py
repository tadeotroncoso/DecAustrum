import sqlite3

from app.evidence_store import EvidenceStore


def test_initialize_creates_decisions_table(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)

    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(authorization_decisions)"
        ).fetchall()

    column_names = {
        column[1]
        for column in columns
    }

    assert column_names == {
        "decision_id",
        "evaluated_at",
        "decision",
        "policy_id",
        "policy_version",
        "reason",
        "evidence_json",
        "agent",
        "action",
        "context_json",
    }
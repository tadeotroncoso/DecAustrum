import sqlite3

from app.evidence_store import EvidenceStore


def test_database_enables_operational_safety_pragmas(tmp_path):
    store = EvidenceStore(tmp_path / "decaustrum.db")
    store.initialize()

    with store.database.connect() as connection:
        foreign_keys = connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()[0]
        busy_timeout = connection.execute(
            "PRAGMA busy_timeout"
        ).fetchone()[0]
        journal_mode = connection.execute(
            "PRAGMA journal_mode"
        ).fetchone()[0]
        synchronous = connection.execute(
            "PRAGMA synchronous"
        ).fetchone()[0]

    assert foreign_keys == 1
    assert busy_timeout == 5000
    assert journal_mode.lower() == "wal"
    assert synchronous == 1


def test_initialized_database_is_ready(tmp_path):
    store = EvidenceStore(tmp_path / "decaustrum.db")
    store.initialize()

    assert store.check_readiness() is True


def test_missing_database_is_not_ready(tmp_path):
    store = EvidenceStore(tmp_path / "missing.db")

    assert store.check_readiness() is False
    assert not store.database_path.exists()


def test_database_without_required_schema_is_not_ready(tmp_path):
    database_path = tmp_path / "incomplete.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("CREATE TABLE example (id INTEGER)")

    store = EvidenceStore(database_path)

    assert store.check_readiness() is False

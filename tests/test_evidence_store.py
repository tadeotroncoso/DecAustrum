import sqlite3
from app.evidence_store import EvidenceStore
import json
from datetime import datetime, timezone
from uuid import uuid4

from app.authorization_models import AuthorizationResponse
from app.decision_models import ConditionEvidence


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

def test_save_persists_authorization_decision(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    decision_id = uuid4()
    evaluated_at = datetime(
        2026,
        8,
        24,
        10,
        30,
        tzinfo=timezone.utc,
    )

    authorization = AuthorizationResponse(
        decision_id=decision_id,
        evaluated_at=evaluated_at,
        decision="DENY",
        policy="unverified-account",
        policy_version=1,
        reason="Bank transfers from unverified accounts are denied.",
        evidence=ConditionEvidence(
            field="account_verified",
            operator="equals",
            actual_value=False,
            expected_value=False,
        ),
        agent="finance-agent",
        action="bank_transfer",
        context={
            "amount": 5000,
            "account_verified": False,
        },
    )

    store.save(authorization)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM authorization_decisions
            WHERE decision_id = ?
            """,
            (str(decision_id),),
        ).fetchone()

    assert row is not None
    assert row["decision_id"] == str(decision_id)
    assert row["evaluated_at"] == evaluated_at.isoformat()
    assert row["decision"] == "DENY"
    assert row["policy_id"] == "unverified-account"
    assert row["policy_version"] == 1
    assert row["agent"] == "finance-agent"
    assert row["action"] == "bank_transfer"

    assert json.loads(row["evidence_json"]) == {
        "field": "account_verified",
        "operator": "equals",
        "actual_value": False,
        "expected_value": False,
    }

    assert json.loads(row["context_json"]) == {
        "amount": 5000,
        "account_verified": False,
    }
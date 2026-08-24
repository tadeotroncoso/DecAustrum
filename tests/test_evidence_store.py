import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.authorization_models import AuthorizationResponse
from app.decision_models import ConditionEvidence
from app.evidence_store import EvidenceStore

def build_authorization() -> AuthorizationResponse:
    return AuthorizationResponse(
        decision_id=uuid4(),
        evaluated_at=datetime(
            2026,
            8,
            24,
            10,
            30,
            tzinfo=timezone.utc,
        ),
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

    authorization = build_authorization()
    decision_id = authorization.decision_id
    evaluated_at = authorization.evaluated_at

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

def test_get_returns_saved_authorization(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()
    store.save(authorization)

    loaded_authorization = store.get(
        authorization.decision_id
    )

    assert loaded_authorization == authorization


def test_get_returns_none_for_unknown_decision(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    loaded_authorization = store.get(uuid4())

    assert loaded_authorization is None
    
def test_list_decisions_is_paginated_and_newest_first(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    first = build_authorization()

    second = first.model_copy(
        update={
            "decision_id": uuid4(),
            "evaluated_at": (
                first.evaluated_at
                + timedelta(seconds=1)
            ),
        }
    )

    store.save(first)
    store.save(second)

    first_page = store.list_decisions(
        limit=1,
        offset=0,
    )
    second_page = store.list_decisions(
        limit=1,
        offset=1,
    )

    assert first_page == [second]
    assert second_page == [first]
    assert store.count() == 2

def test_initialize_creates_approval_requests_table(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)

    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(approval_requests)"
        ).fetchall()

        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(approval_requests)"
        ).fetchall()

    column_names = {
        column[1]
        for column in columns
    }

    assert column_names == {
        "decision_id",
        "status",
        "requested_at",
        "resolved_at",
        "resolved_by",
    }

    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == "authorization_decisions"
    assert foreign_keys[0][3] == "decision_id"
    assert foreign_keys[0][4] == "decision_id"
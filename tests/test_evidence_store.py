import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from app.idempotency import IdempotencyRecord

from app.approval_models import ApprovalRecord
from app.authorization_models import AuthorizationResponse
from app.decision_models import (
    ConditionEvidence,
    PolicyEvidence,
    PolicyTraceEntry,
)
from app.evidence_store import EvidenceStore
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
)

def build_authorization() -> AuthorizationResponse:
    reason = (
        "Bank transfers from unverified accounts are denied."
    )

    evidence = PolicyEvidence(
        match="all",
        conditions=[
            ConditionEvidence(
                field="account_verified",
                operator="equals",
                actual_value=False,
                expected_value=False,
                matched=True,
            )
        ],
    )

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
        reason=reason,
        evidence=evidence,
        trace=[
            PolicyTraceEntry(
                policy_id="unverified-account",
                policy_version=1,
                decision="DENY",
                reason=reason,
                matched=True,
                evidence=evidence,
            )
        ],
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
        "trace_json",
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
    stored_trace = json.loads(row["trace_json"])

    assert len(stored_trace) == 1
    assert stored_trace[0]["policy_id"] == "unverified-account"
    assert stored_trace[0]["decision"] == "DENY"
    assert stored_trace[0]["matched"] is True

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


def test_save_and_get_pending_approval(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()
    store.save(authorization)

    approval = ApprovalRecord(
        decision_id=authorization.decision_id,
        status="PENDING",
        requested_at=authorization.evaluated_at,
    )

    store.save_approval(approval)

    stored_approval = store.get_approval(
        authorization.decision_id
    )

    assert stored_approval == approval


def test_approval_requires_existing_decision(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    approval = ApprovalRecord(
        decision_id=uuid4(),
        status="PENDING",
        requested_at=datetime.now(timezone.utc),
    )

    with pytest.raises(sqlite3.IntegrityError):
        store.save_approval(approval)


def test_combined_save_rolls_back_on_mismatched_approval(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()

    approval = ApprovalRecord(
        decision_id=uuid4(),
        status="PENDING",
        requested_at=authorization.evaluated_at,
    )

    with pytest.raises(ValueError):
        store.save_authorization_with_approval(
            authorization=authorization,
            approval=approval,
        )

    assert store.get(authorization.decision_id) is None

def test_resolve_pending_approval(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    authorization = build_authorization()
    approval = ApprovalRecord(
        decision_id=authorization.decision_id,
        status="PENDING",
        requested_at=authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=authorization,
        approval=approval,
    )

    resolved_at = (
        approval.requested_at
        + timedelta(minutes=1)
    )

    resolved = store.resolve_approval(
        decision_id=approval.decision_id,
        status="APPROVED",
        resolved_by="security-admin",
        resolved_at=resolved_at,
    )

    assert resolved.status == "APPROVED"
    assert resolved.resolved_by == "security-admin"
    assert resolved.resolved_at == resolved_at


def test_cannot_resolve_approval_twice(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    authorization = build_authorization()
    approval = ApprovalRecord(
        decision_id=authorization.decision_id,
        status="PENDING",
        requested_at=authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=authorization,
        approval=approval,
    )

    store.resolve_approval(
        decision_id=approval.decision_id,
        status="APPROVED",
        resolved_by="first-admin",
        resolved_at=approval.requested_at,
    )

    with pytest.raises(ApprovalAlreadyResolvedError):
        store.resolve_approval(
            decision_id=approval.decision_id,
            status="REJECTED",
            resolved_by="second-admin",
            resolved_at=approval.requested_at,
        )


def test_resolve_unknown_approval_fails(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    with pytest.raises(ApprovalNotFoundError):
        store.resolve_approval(
            decision_id=uuid4(),
            status="APPROVED",
            resolved_by="security-admin",
            resolved_at=datetime.now(timezone.utc),
        )

def test_initialize_migrates_legacy_decisions_table(
    tmp_path,
):
    database_path = tmp_path / "legacy.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE authorization_decisions (
                decision_id TEXT PRIMARY KEY,
                evaluated_at TEXT NOT NULL,
                decision TEXT NOT NULL,
                policy_id TEXT,
                policy_version INTEGER,
                reason TEXT NOT NULL,
                evidence_json TEXT,
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                context_json TEXT NOT NULL
            )
            """
        )

    store = EvidenceStore(database_path)
    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(authorization_decisions)"
        ).fetchall()

    assert "trace_json" in {
        column[1]
        for column in columns
    }

def test_initialize_creates_idempotency_records_table(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)

    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(idempotency_records)"
        ).fetchall()

        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(idempotency_records)"
        ).fetchall()

    column_names = {
        column[1]
        for column in columns
    }

    assert column_names == {
        "idempotency_key",
        "request_fingerprint",
        "decision_id",
        "created_at",
    }

    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == "authorization_decisions"
    assert foreign_keys[0][3] == "decision_id"
    assert foreign_keys[0][4] == "decision_id"


def test_atomic_save_persists_idempotency_record(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()

    idempotency_record = IdempotencyRecord(
        idempotency_key="authorization-request-123",
        request_fingerprint="fingerprint-123",
        decision_id=authorization.decision_id,
        created_at=authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=authorization,
        approval=None,
        idempotency_record=idempotency_record,
    )

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT *
            FROM idempotency_records
            WHERE idempotency_key = ?
            """,
            ("authorization-request-123",),
        ).fetchone()

    assert row is not None
    assert row["request_fingerprint"] == "fingerprint-123"
    assert row["decision_id"] == str(
        authorization.decision_id
    )
    assert row["created_at"] == (
        authorization.evaluated_at.isoformat()
    )


def test_duplicate_idempotency_key_rolls_back_authorization(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    first_authorization = build_authorization()
    second_authorization = build_authorization()

    first_record = IdempotencyRecord(
        idempotency_key="duplicate-key",
        request_fingerprint="first-fingerprint",
        decision_id=first_authorization.decision_id,
        created_at=first_authorization.evaluated_at,
    )

    second_record = IdempotencyRecord(
        idempotency_key="duplicate-key",
        request_fingerprint="second-fingerprint",
        decision_id=second_authorization.decision_id,
        created_at=second_authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=first_authorization,
        approval=None,
        idempotency_record=first_record,
    )

    with pytest.raises(sqlite3.IntegrityError):
        store.save_authorization_with_approval(
            authorization=second_authorization,
            approval=None,
            idempotency_record=second_record,
        )

    assert store.get(
        second_authorization.decision_id
    ) is None


def test_get_idempotency_record_returns_saved_record(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()

    expected_record = IdempotencyRecord(
        idempotency_key="saved-key",
        request_fingerprint="saved-fingerprint",
        decision_id=authorization.decision_id,
        created_at=authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=authorization,
        approval=None,
        idempotency_record=expected_record,
    )

    loaded_record = store.get_idempotency_record(
        "saved-key"
    )

    assert loaded_record == expected_record


def test_get_idempotency_record_returns_none_for_unknown_key(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    loaded_record = store.get_idempotency_record(
        "unknown-key"
    )

    assert loaded_record is None
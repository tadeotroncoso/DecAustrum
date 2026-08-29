import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from app.project_models import (
    DEFAULT_PROJECT_ID,
    Project,
)

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
    PolicyVersionConflictError,
)
from app.policy_models import Policy

from app.api_keys import (
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
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
        project_id=DEFAULT_PROJECT_ID,
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

def build_project() -> Project:
    return Project(
        project_id=uuid4(),
        name="Acme Production",
        status="ACTIVE",
        created_at=datetime(
            2026,
            8,
            28,
            10,
            0,
            tzinfo=timezone.utc,
        ),
    )

def build_project_api_key(
    project_id: UUID,
) -> ProjectApiKeyRecord:
    secret = generate_project_api_key()

    return ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=project_id,
        key_prefix=get_api_key_prefix(secret),
        key_hash=hash_api_key(secret),
        created_at=datetime(
            2026,
            8,
            28,
            10,
            5,
            tzinfo=timezone.utc,
        ),
    )


def build_policy(
    *,
    policy_id: str = "refund-limit",
    version: int = 1,
    amount: int = 500,
    decision: str = "REQUIRE_APPROVAL",
) -> Policy:
    return Policy.model_validate(
        {
            "id": policy_id,
            "version": version,
            "action": "refund_payment",
            "match": "all",
            "conditions": [
                {
                    "field": "amount",
                    "operator": "greater_than",
                    "value": amount,
                }
            ],
            "decision": decision,
            "reason": f"Refund policy version {version}.",
        }
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
        "project_id",
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
    assert row["project_id"] == str(DEFAULT_PROJECT_ID)
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
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    )
    assert loaded_authorization == authorization


def test_get_returns_none_for_unknown_decision(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    loaded_authorization = store.get(
        decision_id=uuid4(),
        project_id=DEFAULT_PROJECT_ID,
    )

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
        project_id=first.project_id,
        limit=1,
        offset=0,
    )

    second_page = store.list_decisions(
        project_id=first.project_id,
        limit=1,
        offset=1,
    )

    assert first_page == [second]
    assert second_page == [first]

    assert store.count(
        project_id=first.project_id
    ) == 2

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
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
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

    assert store.get(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    ) is None

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
        project_id=authorization.project_id,
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
        project_id=authorization.project_id,
        status="APPROVED",
        resolved_by="first-admin",
        resolved_at=approval.requested_at,
    )

    with pytest.raises(ApprovalAlreadyResolvedError):
        store.resolve_approval(
            decision_id=approval.decision_id,
            project_id=authorization.project_id,
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
            project_id=DEFAULT_PROJECT_ID,
        )

def test_approval_resolution_is_scoped_to_project(
    tmp_path,
):
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

    with pytest.raises(ApprovalNotFoundError):
        store.resolve_approval(
            decision_id=approval.decision_id,
            project_id=uuid4(),
            status="APPROVED",
            resolved_by="wrong-project-admin",
            resolved_at=datetime.now(timezone.utc),
        )

    stored_approval = store.get_approval(
        decision_id=approval.decision_id,
        project_id=authorization.project_id,
    )

    assert stored_approval is not None
    assert stored_approval.status == "PENDING"

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

    column_names = {
        column[1]
        for column in columns
    }

    assert "trace_json" in column_names
    assert "project_id" in column_names

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

    primary_key_columns = {
        column[1]
        for column in columns
        if column[5] > 0
    }

    assert column_names == {
        "project_id",
        "idempotency_key",
        "request_fingerprint",
        "decision_id",
        "created_at",
    }

    assert primary_key_columns == {
        "project_id",
        "idempotency_key",
    }

    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == (
        "authorization_decisions"
    )
    assert foreign_keys[0][3] == "decision_id"
    assert foreign_keys[0][4] == "decision_id"


def test_initialize_migrates_legacy_idempotency_records(
    tmp_path,
):
    database_path = tmp_path / "legacy.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()
    store.save(authorization)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "DROP TABLE idempotency_records"
        )

        connection.execute(
            """
            CREATE TABLE idempotency_records (
                idempotency_key TEXT PRIMARY KEY,
                request_fingerprint TEXT NOT NULL,
                decision_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                FOREIGN KEY (decision_id)
                    REFERENCES authorization_decisions(decision_id)
            )
            """
        )

        connection.execute(
            """
            INSERT INTO idempotency_records (
                idempotency_key,
                request_fingerprint,
                decision_id,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                "legacy-key",
                "legacy-fingerprint",
                str(authorization.decision_id),
                authorization.evaluated_at.isoformat(),
            ),
        )

    store.initialize()

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row

        columns = connection.execute(
            "PRAGMA table_info(idempotency_records)"
        ).fetchall()

        row = connection.execute(
            """
            SELECT *
            FROM idempotency_records
            WHERE project_id = ?
            AND idempotency_key = ?
            """,
            (
                str(authorization.project_id),
                "legacy-key",
            ),
        ).fetchone()

    column_names = {
        column[1]
        for column in columns
    }

    primary_key_columns = {
        column[1]
        for column in columns
        if column[5] > 0
    }

    assert "project_id" in column_names
    assert primary_key_columns == {
        "project_id",
        "idempotency_key",
    }

    assert row is not None
    assert row["project_id"] == str(
        authorization.project_id
    )
    assert row["request_fingerprint"] == (
        "legacy-fingerprint"
    )
    assert row["decision_id"] == str(
        authorization.decision_id
    )


def test_atomic_save_persists_idempotency_record(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()

    idempotency_record = IdempotencyRecord(
        project_id=authorization.project_id,
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
            WHERE project_id = ?
            AND idempotency_key = ?
            """,
            (
                str(authorization.project_id),
                "authorization-request-123",
            ),
        ).fetchone()

    assert row is not None
    assert row["request_fingerprint"] == "fingerprint-123"
    assert row["decision_id"] == str(
        authorization.decision_id
    )
    assert row["created_at"] == (
        authorization.evaluated_at.isoformat()
    )
    assert row["project_id"] == str(
        authorization.project_id
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
        project_id=first_authorization.project_id,
        idempotency_key="duplicate-key",
        request_fingerprint="first-fingerprint",
        decision_id=first_authorization.decision_id,
        created_at=first_authorization.evaluated_at,
    )

    second_record = IdempotencyRecord(
        project_id=second_authorization.project_id,
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
        decision_id=second_authorization.decision_id,
        project_id=second_authorization.project_id,
    ) is None


def test_get_idempotency_record_returns_saved_record(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    authorization = build_authorization()

    expected_record = IdempotencyRecord(
        project_id=authorization.project_id,
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
        project_id=authorization.project_id,
        idempotency_key="saved-key",
    )

    assert loaded_record == expected_record


def test_get_idempotency_record_returns_none_for_unknown_key(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    loaded_record = store.get_idempotency_record(
        project_id=DEFAULT_PROJECT_ID,
        idempotency_key="unknown-key",
    )

    assert loaded_record is None

def test_initialize_creates_projects_table(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)

    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(projects)"
        ).fetchall()

    column_names = {
        column[1]
        for column in columns
    }

    assert column_names == {
        "project_id",
        "name",
        "status",
        "created_at",
        "updated_at",
    }


def test_projects_table_rejects_invalid_status(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    with pytest.raises(sqlite3.IntegrityError):
        with sqlite3.connect(database_path) as connection:
            connection.execute(
                """
                INSERT INTO projects (
                    project_id,
                    name,
                    status,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    "Invalid Project",
                    "UNKNOWN",
                    "2026-08-28T10:00:00+00:00",
                    "2026-08-28T10:00:00+00:00",
                ),
            )


def test_save_project_persists_project(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project()

    store.save_project(project)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT *
            FROM projects
            WHERE project_id = ?
            """,
            (str(project.project_id),),
        ).fetchone()

    assert row is not None
    assert row["project_id"] == str(project.project_id)
    assert row["name"] == "Acme Production"
    assert row["status"] == "ACTIVE"
    assert row["created_at"] == (
        project.created_at.isoformat()
    )
    assert row["updated_at"] == (
        project.updated_at.isoformat()
    )


def test_get_project_returns_saved_project(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project()
    store.save_project(project)

    loaded_project = store.get_project(
        project.project_id
    )

    assert loaded_project == project


def test_get_project_returns_none_when_unknown(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    loaded_project = store.get_project(uuid4())

    assert loaded_project is None


def test_initialize_migrates_legacy_projects_table(
    tmp_path,
):
    database_path = tmp_path / "legacy.db"
    project_id = uuid4()
    created_at = "2026-08-28T10:00:00+00:00"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE projects (
                project_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO projects (
                project_id,
                name,
                status,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                str(project_id),
                "Legacy Project",
                "ACTIVE",
                created_at,
            ),
        )

    store = EvidenceStore(database_path)
    store.initialize()

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM projects
            WHERE project_id = ?
            """,
            (str(project_id),),
        ).fetchone()

    assert row is not None
    assert row["updated_at"] == created_at
    assert store.get_project(project_id) is not None


def test_list_and_count_projects_support_status_filter(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    base_time = datetime(
        2026,
        8,
        28,
        10,
        0,
        tzinfo=timezone.utc,
    )

    first = Project(
        project_id=uuid4(),
        name="First",
        status="ACTIVE",
        created_at=base_time,
    )
    second = Project(
        project_id=uuid4(),
        name="Second",
        status="DISABLED",
        created_at=base_time + timedelta(minutes=1),
    )
    third = Project(
        project_id=uuid4(),
        name="Third",
        status="ACTIVE",
        created_at=base_time + timedelta(minutes=2),
    )

    for project in (first, second, third):
        store.save_project(project)

    first_page = store.list_projects(
        limit=2,
        offset=0,
    )
    second_page = store.list_projects(
        limit=2,
        offset=2,
    )

    assert first_page == [third, second]
    assert second_page == [first]
    assert store.count_projects() == 3
    assert store.list_projects(status="ACTIVE") == [
        third,
        first,
    ]
    assert store.count_projects(status="ACTIVE") == 2
    assert store.list_projects(status="DISABLED") == [
        second
    ]
    assert store.count_projects(status="DISABLED") == 1


def test_update_project_status_is_idempotent(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    project = build_project()
    store.save_project(project)

    disabled_at = project.created_at + timedelta(minutes=1)
    repeated_at = project.created_at + timedelta(minutes=2)
    reactivated_at = project.created_at + timedelta(minutes=3)

    disabled = store.update_project_status(
        project_id=project.project_id,
        status="DISABLED",
        updated_at=disabled_at,
    )
    repeated = store.update_project_status(
        project_id=project.project_id,
        status="DISABLED",
        updated_at=repeated_at,
    )
    reactivated = store.update_project_status(
        project_id=project.project_id,
        status="ACTIVE",
        updated_at=reactivated_at,
    )

    assert disabled is not None
    assert disabled.status == "DISABLED"
    assert disabled.updated_at == disabled_at
    assert repeated == disabled
    assert reactivated is not None
    assert reactivated.status == "ACTIVE"
    assert reactivated.updated_at == reactivated_at
    assert reactivated.created_at == project.created_at


def test_update_project_status_returns_none_when_unknown(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    updated = store.update_project_status(
        project_id=uuid4(),
        status="DISABLED",
        updated_at=datetime.now(timezone.utc),
    )

    assert updated is None


def test_initialize_creates_project_api_keys_table(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)

    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(project_api_keys)"
        ).fetchall()

        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(project_api_keys)"
        ).fetchall()

    column_names = {
        column[1]
        for column in columns
    }

    assert column_names == {
        "api_key_id",
        "project_id",
        "key_prefix",
        "key_hash",
        "created_at",
        "revoked_at",
    }

    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == "projects"
    assert foreign_keys[0][3] == "project_id"
    assert foreign_keys[0][4] == "project_id"


def test_save_project_api_key_persists_hash(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project()
    api_key = build_project_api_key(
        project.project_id
    )

    store.save_project(project)
    store.save_project_api_key(api_key)

    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row

        row = connection.execute(
            """
            SELECT *
            FROM project_api_keys
            WHERE api_key_id = ?
            """,
            (str(api_key.api_key_id),),
        ).fetchone()

    assert row is not None
    assert row["project_id"] == str(project.project_id)
    assert row["key_prefix"] == api_key.key_prefix
    assert row["key_hash"] == api_key.key_hash
    assert row["revoked_at"] is None


def test_list_project_api_keys_is_scoped_and_paginated(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    first_project = build_project()
    second_project = build_project()

    store.save_project(first_project)
    store.save_project(second_project)

    first_key = build_project_api_key(
        first_project.project_id
    )

    second_key = build_project_api_key(
        first_project.project_id
    ).model_copy(
        update={
            "created_at": (
                first_key.created_at
                + timedelta(seconds=1)
            )
        }
    )

    other_project_key = build_project_api_key(
        second_project.project_id
    )

    store.save_project_api_key(first_key)
    store.save_project_api_key(second_key)
    store.save_project_api_key(other_project_key)

    first_page = store.list_project_api_keys(
        project_id=first_project.project_id,
        limit=1,
        offset=0,
    )

    second_page = store.list_project_api_keys(
        project_id=first_project.project_id,
        limit=1,
        offset=1,
    )

    assert [
        key.api_key_id
        for key in first_page
    ] == [second_key.api_key_id]

    assert [
        key.api_key_id
        for key in second_page
    ] == [first_key.api_key_id]

    assert store.count_project_api_keys(
        first_project.project_id
    ) == 2

    assert store.count_project_api_keys(
        second_project.project_id
    ) == 1

    assert "key_hash" not in first_page[0].model_dump()


def test_revoke_project_api_key_is_idempotent(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    project = build_project()
    api_key = build_project_api_key(project.project_id)

    store.save_project(project)
    store.save_project_api_key(api_key)

    revoked_at = api_key.created_at + timedelta(minutes=1)

    first_result = store.revoke_project_api_key(
        project_id=project.project_id,
        api_key_id=api_key.api_key_id,
        revoked_at=revoked_at,
    )

    second_result = store.revoke_project_api_key(
        project_id=project.project_id,
        api_key_id=api_key.api_key_id,
        revoked_at=revoked_at + timedelta(minutes=1),
    )

    assert first_result is not None
    assert first_result.revoked_at == revoked_at
    assert second_result == first_result

    assert store.get_active_project_by_api_key_hash(
        api_key.key_hash
    ) is None


def test_revoke_project_api_key_is_scoped_to_project(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    first_project = build_project()
    second_project = build_project()
    api_key = build_project_api_key(
        first_project.project_id
    )

    store.save_project(first_project)
    store.save_project(second_project)
    store.save_project_api_key(api_key)

    result = store.revoke_project_api_key(
        project_id=second_project.project_id,
        api_key_id=api_key.api_key_id,
        revoked_at=datetime.now(timezone.utc),
    )

    assert result is None
    assert store.get_active_project_by_api_key_hash(
        api_key.key_hash
    ) == first_project


def test_save_project_api_key_rejects_unknown_project(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    api_key = build_project_api_key(uuid4())

    with pytest.raises(sqlite3.IntegrityError):
        store.save_project_api_key(api_key)


def test_api_key_hash_returns_active_project(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project()
    api_key = build_project_api_key(
        project.project_id
    )

    store.save_project(project)
    store.save_project_api_key(api_key)

    loaded_project = (
        store.get_active_project_by_api_key_hash(
            api_key.key_hash
        )
    )

    assert loaded_project == project


def test_revoked_api_key_does_not_return_project(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project()
    api_key = build_project_api_key(
        project.project_id
    ).model_copy(
        update={
            "revoked_at": datetime(
                2026,
                8,
                28,
                11,
                0,
                tzinfo=timezone.utc,
            )
        }
    )

    store.save_project(project)
    store.save_project_api_key(api_key)

    loaded_project = (
        store.get_active_project_by_api_key_hash(
            api_key.key_hash
        )
    )

    assert loaded_project is None


def test_disabled_project_is_not_authenticated(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project().model_copy(
        update={"status": "DISABLED"}
    )

    api_key = build_project_api_key(
        project.project_id
    )

    store.save_project(project)
    store.save_project_api_key(api_key)

    loaded_project = (
        store.get_active_project_by_api_key_hash(
            api_key.key_hash
        )
    )

    assert loaded_project is None


def test_save_project_with_api_key_persists_both(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project()
    api_key = build_project_api_key(
        project.project_id
    )

    store.save_project_with_api_key(
        project=project,
        api_key=api_key,
    )

    assert store.get_project(
        project.project_id
    ) == project

    assert (
        store.get_active_project_by_api_key_hash(
            api_key.key_hash
        )
        == project
    )


def test_save_project_with_api_key_rejects_mismatch(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    project = build_project()
    api_key = build_project_api_key(uuid4())

    with pytest.raises(
        ValueError,
        match=(
            "API key project_id must match "
            "project project_id."
        ),
    ):
        store.save_project_with_api_key(
            project=project,
            api_key=api_key,
        )

    assert store.get_project(
        project.project_id
    ) is None


def test_duplicate_api_key_hash_rolls_back_project(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    first_project = build_project()
    first_api_key = build_project_api_key(
        first_project.project_id
    )

    store.save_project_with_api_key(
        project=first_project,
        api_key=first_api_key,
    )

    second_project = build_project()

    duplicate_api_key = first_api_key.model_copy(
        update={
            "api_key_id": uuid4(),
            "project_id": second_project.project_id,
        }
    )

    with pytest.raises(sqlite3.IntegrityError):
        store.save_project_with_api_key(
            project=second_project,
            api_key=duplicate_api_key,
        )

    assert store.get_project(
        second_project.project_id
    ) is None

def test_decision_queries_are_scoped_to_project(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    first_authorization = build_authorization()

    second_authorization = (
        first_authorization.model_copy(
            update={
                "decision_id": uuid4(),
                "project_id": uuid4(),
            }
        )
    )

    store.save(first_authorization)
    store.save(second_authorization)

    assert store.get(
        decision_id=first_authorization.decision_id,
        project_id=second_authorization.project_id,
    ) is None

    assert store.list_decisions(
        project_id=first_authorization.project_id
    ) == [first_authorization]

    assert store.list_decisions(
        project_id=second_authorization.project_id
    ) == [second_authorization]

    assert store.count(
        project_id=first_authorization.project_id
    ) == 1

    assert store.count(
        project_id=second_authorization.project_id
    ) == 1

def test_approval_queries_are_scoped_to_project(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    first_authorization = build_authorization()

    second_authorization = (
        first_authorization.model_copy(
            update={
                "decision_id": uuid4(),
                "project_id": uuid4(),
            }
        )
    )

    first_approval = ApprovalRecord(
        decision_id=first_authorization.decision_id,
        status="PENDING",
        requested_at=first_authorization.evaluated_at,
    )

    second_approval = ApprovalRecord(
        decision_id=second_authorization.decision_id,
        status="PENDING",
        requested_at=second_authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=first_authorization,
        approval=first_approval,
    )
    store.save_authorization_with_approval(
        authorization=second_authorization,
        approval=second_approval,
    )

    assert store.get_approval(
        decision_id=first_authorization.decision_id,
        project_id=second_authorization.project_id,
    ) is None

    assert store.list_approvals(
        project_id=first_authorization.project_id,
    ) == [first_approval]

    assert store.list_approvals(
        project_id=second_authorization.project_id,
    ) == [second_approval]

    assert store.count_approvals(
        project_id=first_authorization.project_id,
    ) == 1

    assert store.count_approvals(
        project_id=second_authorization.project_id,
    ) == 1

def test_idempotency_keys_are_scoped_to_project(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    first_authorization = build_authorization()

    second_authorization = (
        first_authorization.model_copy(
            update={
                "decision_id": uuid4(),
                "project_id": uuid4(),
            }
        )
    )

    first_record = IdempotencyRecord(
        project_id=first_authorization.project_id,
        idempotency_key="shared-key",
        request_fingerprint="first-fingerprint",
        decision_id=first_authorization.decision_id,
        created_at=first_authorization.evaluated_at,
    )

    second_record = IdempotencyRecord(
        project_id=second_authorization.project_id,
        idempotency_key="shared-key",
        request_fingerprint="second-fingerprint",
        decision_id=second_authorization.decision_id,
        created_at=second_authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=first_authorization,
        approval=None,
        idempotency_record=first_record,
    )

    store.save_authorization_with_approval(
        authorization=second_authorization,
        approval=None,
        idempotency_record=second_record,
    )

    assert store.get_idempotency_record(
        project_id=first_authorization.project_id,
        idempotency_key="shared-key",
    ) == first_record

    assert store.get_idempotency_record(
        project_id=second_authorization.project_id,
        idempotency_key="shared-key",
    ) == second_record


def test_initialize_creates_project_policies_table(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(project_policies)"
        ).fetchall()

        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(project_policies)"
        ).fetchall()

    assert {
        column[1]
        for column in columns
    } == {
        "project_id",
        "policy_id",
        "version",
        "policy_json",
        "enabled",
        "updated_at",
    }

    assert {
        column[1]
        for column in columns
        if column[5] > 0
    } == {
        "project_id",
        "policy_id",
    }

    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == "projects"
    assert foreign_keys[0][3] == "project_id"
    assert foreign_keys[0][4] == "project_id"


def test_project_policies_are_isolated_by_project(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    first_project = build_project()
    second_project = build_project()
    seeded_at = datetime.now(timezone.utc)
    initial_policy = build_policy()

    store.save_project(first_project)
    store.save_project(second_project)

    store.seed_project_policies(
        project_id=first_project.project_id,
        policies=[initial_policy],
        seeded_at=seeded_at,
    )
    store.seed_project_policies(
        project_id=second_project.project_id,
        policies=[initial_policy],
        seeded_at=seeded_at,
    )

    updated_policy = build_policy(
        version=2,
        amount=100,
        decision="DENY",
    )

    store.save_project_policy(
        project_id=first_project.project_id,
        policy=updated_policy,
        updated_at=seeded_at + timedelta(minutes=1),
    )

    assert store.get_project_policy(
        project_id=first_project.project_id,
        policy_id="refund-limit",
    ) == updated_policy

    assert store.get_project_policy(
        project_id=second_project.project_id,
        policy_id="refund-limit",
    ) == initial_policy


def test_project_policy_requires_next_version(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    project = build_project()
    policy = build_policy()

    store.save_project(project)
    store.seed_project_policies(
        project_id=project.project_id,
        policies=[policy],
        seeded_at=project.created_at,
    )

    with pytest.raises(
        PolicyVersionConflictError
    ) as exc_info:
        store.save_project_policy(
            project_id=project.project_id,
            policy=policy,
            updated_at=datetime.now(timezone.utc),
        )

    assert exc_info.value.expected_version == 2
    assert exc_info.value.provided_version == 1


def test_disabled_policy_is_not_reseeded(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    project = build_project()
    policy = build_policy()
    disabled_at = project.created_at + timedelta(minutes=1)

    store.save_project(project)
    store.seed_project_policies(
        project_id=project.project_id,
        policies=[policy],
        seeded_at=project.created_at,
    )

    first_result = store.disable_project_policy(
        project_id=project.project_id,
        policy_id=policy.id,
        updated_at=disabled_at,
    )

    store.seed_project_policies(
        project_id=project.project_id,
        policies=[policy],
        seeded_at=disabled_at + timedelta(minutes=1),
    )

    second_result = store.disable_project_policy(
        project_id=project.project_id,
        policy_id=policy.id,
        updated_at=disabled_at + timedelta(minutes=2),
    )

    assert first_result is not None
    assert first_result.enabled is False
    assert second_result == first_result
    assert store.list_project_policies(
        project.project_id
    ) == []

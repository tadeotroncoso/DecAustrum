import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.approval_models import ApprovalRecord
from app.audit_models import AuditContext
from app.authorization_models import (
    AuthorizationRequest,
    AuthorizationResponse,
)
from app.bootstrap import bootstrap_default_project
from app.evidence_store import EvidenceStore
from app.execution_grants import (
    build_execution_grant_token,
    hash_execution_grant_token,
)
from app.execution_models import (
    ExecutionGrantPayload,
    ExecutionGrantRecord,
)
from app.idempotency import build_request_fingerprint
from app.project_models import DEFAULT_PROJECT_ID


SECRET = "execution-grant-store-secret-at-least-32-bytes"


def build_authorization(
    evaluated_at: datetime | None = None,
) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision_id=uuid4(),
        project_id=DEFAULT_PROJECT_ID,
        evaluated_at=evaluated_at or datetime.now(timezone.utc),
        decision="REQUIRE_APPROVAL",
        policy="large-transfer",
        policy_version=1,
        reason="Large transfer requires approval.",
        evidence=None,
        agent="finance-agent",
        action="bank_transfer",
        context={
            "amount": 25_000,
            "account_verified": True,
        },
        trace=[],
    )


def seed_pending(store: EvidenceStore):
    bootstrap_default_project(store=store, api_key="store-api-key")
    authorization = build_authorization()
    approval = ApprovalRecord(
        decision_id=authorization.decision_id,
        status="PENDING",
        requested_at=authorization.evaluated_at,
        expires_at=(
            authorization.evaluated_at + timedelta(hours=1)
        ),
    )
    store.save_authorization_with_approval(
        authorization=authorization,
        approval=approval,
    )
    return authorization, approval


def build_grant(
    authorization: AuthorizationResponse,
) -> ExecutionGrantRecord:
    request = AuthorizationRequest(
        agent=authorization.agent,
        action=authorization.action,
        context=authorization.context,
    )
    payload = ExecutionGrantPayload(
        grant_id=uuid4(),
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
        request_fingerprint=build_request_fingerprint(request),
        issued_at=authorization.evaluated_at + timedelta(minutes=1),
        expires_at=authorization.evaluated_at + timedelta(minutes=6),
    )
    token = build_execution_grant_token(payload, SECRET)
    return ExecutionGrantRecord(
        **payload.model_dump(),
        token_hash=hash_execution_grant_token(token),
    )


def test_initialize_creates_execution_grant_controls(tmp_path):
    database_path = tmp_path / "regtrace.db"
    store = EvidenceStore(database_path)
    store.initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(execution_grants)"
        ).fetchall()
        triggers = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'trigger'
            """
        ).fetchall()

    assert {column[1] for column in columns} == {
        "grant_id",
        "decision_id",
        "project_id",
        "status",
        "request_fingerprint",
        "token_hash",
        "issued_at",
        "expires_at",
        "consumed_at",
        "consumed_by",
    }
    trigger_names = {row[0] for row in triggers}
    assert "require_execution_grant_for_approval" in trigger_names
    assert "protect_approval_lifecycle" in trigger_names
    assert "prevent_approval_delete" in trigger_names
    assert "protect_execution_grant_lifecycle" in trigger_names
    assert "prevent_execution_grant_delete" in trigger_names


def test_database_rejects_approval_without_grant(tmp_path):
    store = EvidenceStore(tmp_path / "regtrace.db")
    store.initialize()
    authorization, _ = seed_pending(store)

    with pytest.raises(sqlite3.IntegrityError):
        with store.database.connect() as connection:
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'APPROVED',
                    resolved_at = ?,
                    resolved_by = 'bypass-attempt'
                WHERE decision_id = ?
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    str(authorization.decision_id),
                ),
            )


def test_approval_grant_and_audit_are_one_transaction(
    tmp_path,
    monkeypatch,
):
    store = EvidenceStore(tmp_path / "regtrace.db")
    store.initialize()
    authorization, _ = seed_pending(store)
    grant = build_grant(authorization)

    def fail_audit(*_args, **_kwargs):
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr(store.audit, "insert", fail_audit)

    with pytest.raises(RuntimeError, match="simulated audit failure"):
        store.approve_approval_with_grant(
            decision_id=authorization.decision_id,
            project_id=authorization.project_id,
            resolved_by="reviewer",
            resolved_at=grant.issued_at,
            grant=grant,
            audit_context=AuditContext(
                actor_type="PROJECT",
                actor_id="reviewer",
            ),
        )

    approval = store.approvals.get(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    )
    assert approval is not None
    assert approval.status == "PENDING"
    assert store.get_execution_grant_for_decision(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    ) is None


def test_approval_rolls_back_when_outbox_write_fails(
    tmp_path,
    monkeypatch,
):
    store = EvidenceStore(tmp_path / "regtrace.db")
    store.initialize()
    authorization, _ = seed_pending(store)
    grant = build_grant(authorization)

    def fail_outbox(*_args, **_kwargs):
        raise RuntimeError("simulated outbox failure")

    monkeypatch.setattr(
        store.webhooks,
        "insert_event_with_deliveries",
        fail_outbox,
    )

    with pytest.raises(RuntimeError, match="simulated outbox failure"):
        store.approve_approval_with_grant(
            decision_id=authorization.decision_id,
            project_id=authorization.project_id,
            resolved_by="reviewer",
            resolved_at=grant.issued_at,
            grant=grant,
            audit_context=AuditContext(
                actor_type="PROJECT",
                actor_id="reviewer",
            ),
        )

    approval = store.approvals.get(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    )
    assert approval is not None
    assert approval.status == "PENDING"
    assert store.get_execution_grant_for_decision(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
    ) is None
    assert store.count_administrative_audit_events(
        project_id=authorization.project_id,
        action="APPROVAL_RESOLVED",
    ) == 0


def test_execution_grant_identity_cannot_change_or_be_deleted(tmp_path):
    store = EvidenceStore(tmp_path / "regtrace.db")
    store.initialize()
    authorization, _ = seed_pending(store)
    grant = build_grant(authorization)
    store.approve_approval_with_grant(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
        resolved_by="reviewer",
        resolved_at=grant.issued_at,
        grant=grant,
        audit_context=AuditContext(
            actor_type="PROJECT",
            actor_id="reviewer",
        ),
    )

    with pytest.raises(sqlite3.IntegrityError):
        with store.database.connect() as connection:
            connection.execute(
                """
                UPDATE execution_grants
                SET request_fingerprint = ?
                WHERE grant_id = ?
                """,
                ("b" * 64, str(grant.grant_id)),
            )

    with pytest.raises(sqlite3.IntegrityError):
        with store.database.connect() as connection:
            connection.execute(
                "DELETE FROM execution_grants WHERE grant_id = ?",
                (str(grant.grant_id),),
            )


def test_consumption_rolls_back_when_outbox_write_fails(
    tmp_path,
    monkeypatch,
):
    store = EvidenceStore(tmp_path / "regtrace.db")
    store.initialize()
    authorization, _ = seed_pending(store)
    grant = build_grant(authorization)
    token = build_execution_grant_token(grant, SECRET)
    store.approve_approval_with_grant(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
        resolved_by="reviewer",
        resolved_at=grant.issued_at,
        grant=grant,
        audit_context=AuditContext(
            actor_type="PROJECT",
            actor_id="reviewer",
        ),
    )

    def fail_outbox(*_args, **_kwargs):
        raise RuntimeError("simulated outbox failure")

    monkeypatch.setattr(
        store.webhooks,
        "insert_event_with_deliveries",
        fail_outbox,
    )

    with pytest.raises(RuntimeError, match="simulated outbox failure"):
        store.consume_execution_grant(
            payload=ExecutionGrantPayload.model_validate(
                grant.model_dump(
                    include={
                        "version",
                        "grant_id",
                        "decision_id",
                        "project_id",
                        "issued_at",
                        "expires_at",
                    }
                )
                | {
                    "request_fingerprint": (
                        grant.request_fingerprint
                    )
                }
            ),
            project_id=authorization.project_id,
            token_hash=hash_execution_grant_token(token),
            request_fingerprint=grant.request_fingerprint,
            consumed_at=grant.issued_at + timedelta(minutes=1),
            consumed_by="runtime",
            audit_context=AuditContext(
                actor_type="PROJECT",
                actor_id="runtime",
            ),
        )

    persisted = store.get_execution_grant(
        grant_id=grant.grant_id,
        project_id=grant.project_id,
    )
    assert persisted is not None
    assert persisted.status == "ACTIVE"
    assert store.count_administrative_audit_events(
        project_id=authorization.project_id,
        action="EXECUTION_GRANT_CONSUMED",
    ) == 0


def test_expiring_approval_is_durable_audited_and_webhooked(tmp_path):
    store = EvidenceStore(tmp_path / "regtrace.db")
    store.initialize()
    authorization, approval = seed_pending(store)
    expired_at = approval.expires_at + timedelta(seconds=1)

    expired = store.expire_due_approvals(
        project_id=authorization.project_id,
        expired_at=expired_at,
    )
    audit = store.list_administrative_audit_events(
        project_id=authorization.project_id,
        action="APPROVAL_EXPIRED",
        limit=10,
    )
    webhooks = store.list_webhook_events(
        project_id=authorization.project_id,
        event_type="approval.expired",
        limit=10,
    )

    assert len(expired) == 1
    assert expired[0].status == "EXPIRED"
    assert expired[0].resolved_by == "regtrace-expiration"
    assert len(audit) == 1
    assert len(webhooks) == 1


def test_initialize_migrates_legacy_approval_schema(tmp_path):
    database_path = tmp_path / "legacy.db"

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE authorization_decisions (
                decision_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                evaluated_at TEXT NOT NULL,
                decision TEXT NOT NULL,
                policy_id TEXT,
                policy_version INTEGER,
                reason TEXT NOT NULL,
                evidence_json TEXT,
                trace_json TEXT NOT NULL DEFAULT '[]',
                agent TEXT NOT NULL,
                action TEXT NOT NULL,
                context_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE approval_requests (
                decision_id TEXT PRIMARY KEY,
                status TEXT NOT NULL CHECK (
                    status IN ('PENDING', 'APPROVED', 'REJECTED')
                ),
                requested_at TEXT NOT NULL,
                resolved_at TEXT,
                resolved_by TEXT,
                FOREIGN KEY (decision_id)
                    REFERENCES authorization_decisions(decision_id)
            )
            """
        )

    EvidenceStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(approval_requests)"
        ).fetchall()
        schema = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'approval_requests'
            """
        ).fetchone()[0]

    assert "expires_at" in {column[1] for column in columns}
    assert "EXPIRED" in schema


def test_initialize_migrates_webhook_event_constraints(tmp_path):
    database_path = tmp_path / "legacy-webhooks.db"
    event_id = uuid4()
    occurred_at = datetime.now(timezone.utc)
    payload = {
        "event_id": str(event_id),
        "project_id": str(DEFAULT_PROJECT_ID),
        "event_type": "authorization.created",
        "occurred_at": occurred_at.isoformat(),
        "resource_type": "AUTHORIZATION_DECISION",
        "resource_id": "legacy-decision",
        "data": {},
        "schema_version": 1,
    }

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE projects (
                project_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO projects (
                project_id, name, status, created_at, updated_at
            ) VALUES (?, 'Legacy Project', 'ACTIVE', ?, ?)
            """,
            (
                str(DEFAULT_PROJECT_ID),
                occurred_at.isoformat(),
                occurred_at.isoformat(),
            ),
        )
        connection.execute(
            """
            CREATE TABLE webhook_events (
                event_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                event_type TEXT NOT NULL CHECK (
                    event_type IN ('authorization.created')
                ),
                occurred_at TEXT NOT NULL,
                resource_type TEXT NOT NULL CHECK (
                    resource_type IN ('AUTHORIZATION_DECISION')
                ),
                resource_id TEXT NOT NULL,
                schema_version INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO webhook_events (
                event_id,
                project_id,
                event_type,
                occurred_at,
                resource_type,
                resource_id,
                schema_version,
                payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(event_id),
                str(DEFAULT_PROJECT_ID),
                "authorization.created",
                occurred_at.isoformat(),
                "AUTHORIZATION_DECISION",
                "legacy-decision",
                1,
                json.dumps(payload, sort_keys=True),
            ),
        )
        connection.execute(
            """
            CREATE TABLE webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                subscription_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt_count INTEGER NOT NULL,
                failure_count INTEGER NOT NULL,
                redelivery_count INTEGER NOT NULL,
                next_attempt_at TEXT,
                lease_expires_at TEXT,
                delivered_at TEXT,
                last_attempt_at TEXT,
                last_status_code INTEGER,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE webhook_delivery_attempts (
                attempt_id TEXT PRIMARY KEY,
                delivery_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL,
                attempted_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                outcome TEXT NOT NULL,
                status_code INTEGER,
                error TEXT
            )
            """
        )

    EvidenceStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        schema = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'table' AND name = 'webhook_events'
            """
        ).fetchone()[0]
        violations = connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        retained = connection.execute(
            "SELECT payload_json FROM webhook_events WHERE event_id = ?",
            (str(event_id),),
        ).fetchone()

    assert "execution_grant.issued" in schema
    assert "EXECUTION_GRANT" in schema
    assert violations == []
    assert retained is not None
    assert json.loads(retained[0]) == payload

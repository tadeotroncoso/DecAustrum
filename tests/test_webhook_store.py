import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.approval_models import ApprovalRecord
from app.audit_models import AuditContext
from app.authorization_models import AuthorizationResponse
from app.evidence_store import EvidenceStore
from app.project_models import Project
from app.webhook_models import WebhookSubscription
from app.webhooks import build_webhook_event


NOW = datetime(2026, 8, 29, 16, 0, tzinfo=timezone.utc)


def build_project(name: str = "Webhook Project") -> Project:
    return Project(
        project_id=uuid4(),
        name=name,
        status="ACTIVE",
        created_at=NOW,
        updated_at=NOW,
    )


def build_subscription(
    project: Project,
    *,
    event_types=None,
) -> WebhookSubscription:
    return WebhookSubscription(
        subscription_id=uuid4(),
        project_id=project.project_id,
        url="https://hooks.example.com/regtrace",
        event_types=event_types or ["*"],
        created_at=NOW,
        updated_at=NOW,
    )


def build_authorization(
    project: Project,
    *,
    decision: str = "REQUIRE_APPROVAL",
) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision_id=uuid4(),
        project_id=project.project_id,
        evaluated_at=NOW + timedelta(minutes=1),
        decision=decision,
        policy="refund-limit" if decision != "ALLOW" else None,
        policy_version=1 if decision != "ALLOW" else None,
        reason="Large refunds require approval.",
        evidence=None,
        agent="finance-agent",
        action="refund_payment",
        context={"amount": 750},
        trace=[],
    )


def insert_subscription(
    store: EvidenceStore,
    subscription: WebhookSubscription,
) -> None:
    with store.database.connect() as connection:
        store.webhooks.insert_subscription(
            connection,
            subscription,
        )


def test_initialize_creates_webhook_outbox_schema(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()
        }
        subscription_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(webhook_subscriptions)"
            ).fetchall()
        }
        triggers = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'trigger'
                AND tbl_name IN (
                    'webhook_events',
                    'webhook_delivery_attempts'
                )
                """
            ).fetchall()
        }

    assert {
        "webhook_subscriptions",
        "webhook_events",
        "webhook_deliveries",
        "webhook_delivery_attempts",
    } <= tables
    assert "secret" not in subscription_columns
    assert "secret_hash" not in subscription_columns
    assert "secret_version" in subscription_columns
    assert triggers == {
        "prevent_webhook_event_update",
        "prevent_webhook_event_delete",
        "prevent_webhook_attempt_update",
        "prevent_webhook_attempt_delete",
    }


def test_event_creation_materializes_only_matching_deliveries(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    first_project = build_project("First")
    second_project = build_project("Second")
    store.save_project(first_project)
    store.save_project(second_project)
    matching = build_subscription(
        first_project,
        event_types=["authorization.created"],
    )
    non_matching = build_subscription(
        first_project,
        event_types=["approval.resolved"],
    )
    foreign = build_subscription(second_project)

    for subscription in (matching, non_matching, foreign):
        insert_subscription(store, subscription)

    event = build_webhook_event(
        project_id=first_project.project_id,
        event_type="authorization.created",
        occurred_at=NOW,
        resource_type="AUTHORIZATION_DECISION",
        resource_id=str(uuid4()),
        data={"decision": "ALLOW"},
    )

    with store.database.connect() as connection:
        deliveries = (
            store.webhooks.insert_event_with_deliveries(
                connection,
                event,
            )
        )

    assert len(deliveries) == 1
    assert deliveries[0].subscription_id == (
        matching.subscription_id
    )
    assert store.get_webhook_event(
        first_project.project_id,
        event.event_id,
    ) == event
    assert store.get_webhook_event(
        second_project.project_id,
        event.event_id,
    ) is None
    assert store.count_webhook_deliveries(
        project_id=first_project.project_id
    ) == 1
    assert store.count_webhook_deliveries(
        project_id=second_project.project_id
    ) == 0


def test_authorization_and_approval_events_share_transaction(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)
    subscription = build_subscription(project)
    insert_subscription(store, subscription)
    authorization = build_authorization(project)
    approval = ApprovalRecord(
        decision_id=authorization.decision_id,
        status="PENDING",
        requested_at=authorization.evaluated_at,
    )

    store.save_authorization_with_approval(
        authorization=authorization,
        approval=approval,
    )

    events = store.list_webhook_events(
        project.project_id,
        limit=10,
    )

    assert {event.event_type for event in events} == {
        "authorization.created",
        "approval.requested",
    }
    assert store.count_webhook_deliveries(
        project_id=project.project_id
    ) == 2


def test_outbox_failure_rolls_back_authorization(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)
    authorization = build_authorization(
        project,
        decision="ALLOW",
    )

    def fail_outbox(*_args, **_kwargs):
        raise sqlite3.IntegrityError("simulated outbox failure")

    monkeypatch.setattr(
        store.webhooks,
        "insert_event_with_deliveries",
        fail_outbox,
    )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="simulated outbox failure",
    ):
        store.save(authorization)

    assert store.get(
        authorization.decision_id,
        project.project_id,
    ) is None
    assert store.count_webhook_events(project.project_id) == 0


def test_outbox_failure_rolls_back_administrative_mutation(
    tmp_path,
    monkeypatch,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)
    context = AuditContext(
        actor_type="ADMIN",
        actor_id="project-admin",
        reason="Suspend compromised integration.",
    )

    def fail_outbox(*_args, **_kwargs):
        raise sqlite3.IntegrityError("simulated outbox failure")

    monkeypatch.setattr(
        store.webhooks,
        "insert_event_with_deliveries",
        fail_outbox,
    )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="simulated outbox failure",
    ):
        store.update_project_status(
            project_id=project.project_id,
            status="DISABLED",
            updated_at=NOW + timedelta(minutes=1),
            audit_context=context,
        )

    assert store.get_project(project.project_id) == project
    assert store.count_administrative_audit_events(
        project_id=project.project_id,
        action="PROJECT_STATUS_CHANGED",
    ) == 0
    assert store.count_webhook_events(project.project_id) == 0


def test_disabling_subscription_is_idempotent_and_cancels_queue(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)
    subscription = build_subscription(project)
    context = AuditContext(
        actor_type="ADMIN",
        actor_id="webhook-admin",
        reason="Endpoint decommissioned.",
    )
    store.save_webhook_subscription(subscription, context)

    first = store.disable_webhook_subscription(
        project_id=project.project_id,
        subscription_id=subscription.subscription_id,
        disabled_at=NOW + timedelta(minutes=1),
        audit_context=context,
    )
    second = store.disable_webhook_subscription(
        project_id=project.project_id,
        subscription_id=subscription.subscription_id,
        disabled_at=NOW + timedelta(minutes=2),
        audit_context=context,
    )

    assert first == second
    assert first.status == "DISABLED"
    assert store.count_administrative_audit_events(
        project_id=project.project_id,
        action="WEBHOOK_SUBSCRIPTION_DISABLED",
    ) == 1
    deliveries = store.list_webhook_deliveries(
        project_id=project.project_id,
    )
    assert deliveries
    assert all(
        delivery.status == "CANCELLED"
        for delivery in deliveries
    )


def test_webhook_events_cannot_be_changed_or_deleted(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)
    event = build_webhook_event(
        project_id=project.project_id,
        event_type="authorization.created",
        occurred_at=NOW,
        resource_type="AUTHORIZATION_DECISION",
        resource_id=str(uuid4()),
        data={"decision": "ALLOW"},
    )

    with store.database.connect() as connection:
        store.webhooks.insert_event_with_deliveries(
            connection,
            event,
        )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="webhook events are immutable",
        ):
            connection.execute(
                """
                UPDATE webhook_events
                SET event_type = 'approval.resolved'
                WHERE event_id = ?
                """,
                (str(event.event_id),),
            )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="webhook events are immutable",
        ):
            connection.execute(
                "DELETE FROM webhook_events WHERE event_id = ?",
                (str(event.event_id),),
            )


def test_initialize_migrates_existing_audit_constraints(tmp_path):
    database_path = tmp_path / "legacy.db"
    project = build_project()
    event_id = uuid4()

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE projects (
                project_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN ('ACTIVE', 'DISABLED')
                ),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            INSERT INTO projects (
                project_id,
                name,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, 'ACTIVE', ?, ?)
            """,
            (
                str(project.project_id),
                project.name,
                project.created_at.isoformat(),
                project.updated_at.isoformat(),
            ),
        )
        connection.execute(
            """
            CREATE TABLE administrative_audit_events (
                event_id TEXT PRIMARY KEY,
                occurred_at TEXT NOT NULL,
                project_id TEXT NOT NULL,
                actor_type TEXT NOT NULL CHECK (
                    actor_type IN ('ADMIN', 'PROJECT', 'SYSTEM')
                ),
                actor_id TEXT NOT NULL,
                action TEXT NOT NULL CHECK (
                    action IN (
                        'PROJECT_CREATED',
                        'PROJECT_STATUS_CHANGED',
                        'API_KEY_CREATED',
                        'API_KEY_REVOKED',
                        'POLICY_CREATED',
                        'POLICY_UPDATED',
                        'POLICY_DISABLED',
                        'POLICY_ROLLED_BACK',
                        'APPROVAL_RESOLVED'
                    )
                ),
                resource_type TEXT NOT NULL CHECK (
                    resource_type IN (
                        'PROJECT',
                        'API_KEY',
                        'POLICY',
                        'APPROVAL'
                    )
                ),
                resource_id TEXT NOT NULL,
                reason TEXT,
                before_json TEXT,
                after_json TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY (project_id)
                    REFERENCES projects(project_id)
            )
            """
        )
        connection.execute(
            """
            INSERT INTO administrative_audit_events (
                event_id,
                occurred_at,
                project_id,
                actor_type,
                actor_id,
                action,
                resource_type,
                resource_id,
                metadata_json
            )
            VALUES (?, ?, ?, 'ADMIN', 'legacy-admin',
                    'PROJECT_CREATED', 'PROJECT', ?, '{}')
            """,
            (
                str(event_id),
                NOW.isoformat(),
                str(project.project_id),
                str(project.project_id),
            ),
        )

    store = EvidenceStore(database_path)
    store.initialize()
    migrated = store.get_administrative_audit_event(event_id)
    subscription = build_subscription(project)
    store.save_webhook_subscription(
        subscription,
        AuditContext(
            actor_type="ADMIN",
            actor_id="new-admin",
            reason="Create webhook after migration.",
        ),
    )

    assert migrated is not None
    assert migrated.action == "PROJECT_CREATED"
    assert store.count_administrative_audit_events(
        project_id=project.project_id,
        action="WEBHOOK_SUBSCRIPTION_CREATED",
    ) == 1

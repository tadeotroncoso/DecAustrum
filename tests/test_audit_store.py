import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.api_keys import (
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
)
from app.audit import build_audit_event
from app.audit_models import AuditContext
from app.evidence_store import EvidenceStore
from app.policy_models import Policy, PolicyCondition
from app.project_models import Project


AUDIT_TIME = datetime(
    2026,
    8,
    29,
    12,
    0,
    tzinfo=timezone.utc,
)


def build_project(name: str = "Audit Project") -> Project:
    return Project(
        project_id=uuid4(),
        name=name,
        status="ACTIVE",
        created_at=AUDIT_TIME,
        updated_at=AUDIT_TIME,
    )


def build_context() -> AuditContext:
    return AuditContext(
        actor_type="ADMIN",
        actor_id="security-admin",
        reason="Security control change.",
    )


def build_policy() -> Policy:
    return Policy(
        id="refund-limit",
        version=1,
        action="refund_payment",
        match="all",
        conditions=[
            PolicyCondition(
                field="amount",
                operator="greater_than",
                value=500,
            )
        ],
        decision="REQUIRE_APPROVAL",
        reason="Large refunds require approval.",
    )


def test_initialize_creates_immutable_audit_schema(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(administrative_audit_events)"
        ).fetchall()
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(administrative_audit_events)"
        ).fetchall()
        indexes = connection.execute(
            "PRAGMA index_list(administrative_audit_events)"
        ).fetchall()
        triggers = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'trigger'
            AND tbl_name = 'administrative_audit_events'
            """
        ).fetchall()

    assert {column[1] for column in columns} == {
        "event_id",
        "occurred_at",
        "project_id",
        "actor_type",
        "actor_id",
        "action",
        "resource_type",
        "resource_id",
        "reason",
        "before_json",
        "after_json",
        "metadata_json",
    }
    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == "projects"
    assert {index[1] for index in indexes} >= {
        "idx_admin_audit_events_occurred",
        "idx_admin_audit_events_project",
    }
    assert {trigger[0] for trigger in triggers} == {
        "prevent_admin_audit_event_update",
        "prevent_admin_audit_event_delete",
    }


def test_audit_repository_filters_and_paginates(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    first_project = build_project("First")
    second_project = build_project("Second")
    store.save_project(first_project)
    store.save_project(second_project)
    context = build_context()

    first_event = build_audit_event(
        occurred_at=AUDIT_TIME,
        project_id=first_project.project_id,
        context=context,
        action="PROJECT_CREATED",
        resource_type="PROJECT",
        resource_id=str(first_project.project_id),
        after=first_project,
    )
    second_event = build_audit_event(
        occurred_at=AUDIT_TIME + timedelta(minutes=1),
        project_id=second_project.project_id,
        context=context,
        action="PROJECT_STATUS_CHANGED",
        resource_type="PROJECT",
        resource_id=str(second_project.project_id),
        before=second_project,
        after=second_project.model_copy(
            update={"status": "DISABLED"}
        ),
    )

    with store.database.connect() as connection:
        store.audit.insert(connection, first_event)
        store.audit.insert(connection, second_event)

    assert store.get_administrative_audit_event(
        first_event.event_id
    ) == first_event
    assert store.list_administrative_audit_events(
        limit=1,
        offset=0,
    ) == [second_event]
    assert store.list_administrative_audit_events(
        project_id=first_project.project_id,
    ) == [first_event]
    assert store.list_administrative_audit_events(
        action="PROJECT_STATUS_CHANGED",
        resource_type="PROJECT",
        resource_id=str(second_project.project_id),
        actor_type="ADMIN",
        actor_id="security-admin",
        occurred_after=AUDIT_TIME + timedelta(seconds=30),
        occurred_before=AUDIT_TIME + timedelta(minutes=2),
    ) == [second_event]
    assert store.count_administrative_audit_events() == 2
    assert store.count_administrative_audit_events(
        project_id=first_project.project_id,
    ) == 1


def test_audit_events_cannot_be_updated_or_deleted(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)
    event = build_audit_event(
        occurred_at=AUDIT_TIME,
        project_id=project.project_id,
        context=build_context(),
        action="PROJECT_CREATED",
        resource_type="PROJECT",
        resource_id=str(project.project_id),
        after=project,
    )

    with store.database.connect() as connection:
        store.audit.insert(connection, event)

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="administrative audit events are immutable",
        ):
            connection.execute(
                """
                UPDATE administrative_audit_events
                SET actor_id = 'attacker'
                WHERE event_id = ?
                """,
                (str(event.event_id),),
            )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="administrative audit events are immutable",
        ):
            connection.execute(
                """
                DELETE FROM administrative_audit_events
                WHERE event_id = ?
                """,
                (str(event.event_id),),
            )


def test_audit_failure_rolls_back_project_status_change(
    tmp_path,
    monkeypatch,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)

    def fail_audit_insert(*_args, **_kwargs):
        raise sqlite3.IntegrityError("simulated audit failure")

    monkeypatch.setattr(
        store.audit,
        "insert",
        fail_audit_insert,
    )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="simulated audit failure",
    ):
        store.update_project_status(
            project_id=project.project_id,
            status="DISABLED",
            updated_at=AUDIT_TIME + timedelta(minutes=1),
            audit_context=build_context(),
        )

    assert store.get_project(project.project_id) == project


def test_idempotent_mutations_emit_one_effective_event(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    store.save_project(project)
    context = build_context()

    for minute in (1, 2):
        store.update_project_status(
            project_id=project.project_id,
            status="DISABLED",
            updated_at=AUDIT_TIME + timedelta(minutes=minute),
            audit_context=context,
        )

    secret = generate_project_api_key()
    api_key = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=project.project_id,
        key_prefix=get_api_key_prefix(secret),
        key_hash=hash_api_key(secret),
        created_at=AUDIT_TIME,
    )
    store.save_project_api_key(api_key)

    for minute in (3, 4):
        store.revoke_project_api_key(
            project_id=project.project_id,
            api_key_id=api_key.api_key_id,
            revoked_at=AUDIT_TIME + timedelta(minutes=minute),
            audit_context=context,
        )

    policy = build_policy()
    store.seed_project_policies(
        project_id=project.project_id,
        policies=[policy],
        seeded_at=AUDIT_TIME,
    )

    for minute in (5, 6):
        store.disable_project_policy(
            project_id=project.project_id,
            policy_id=policy.id,
            updated_at=AUDIT_TIME + timedelta(minutes=minute),
            audit_context=context,
        )

    assert store.count_administrative_audit_events(
        project_id=project.project_id,
        action="PROJECT_STATUS_CHANGED",
    ) == 1
    assert store.count_administrative_audit_events(
        project_id=project.project_id,
        action="API_KEY_REVOKED",
    ) == 1
    assert store.count_administrative_audit_events(
        project_id=project.project_id,
        action="POLICY_DISABLED",
    ) == 1

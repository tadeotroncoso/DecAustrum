import json
import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.evidence_store import EvidenceStore
from app.exceptions import (
    PolicyVersionAlreadyCurrentError,
    PolicyVersionNotFoundError,
)
from app.policy_models import Policy
from app.project_models import Project


CREATED_AT = datetime(
    2026,
    8,
    29,
    10,
    0,
    tzinfo=timezone.utc,
)


def build_project() -> Project:
    return Project(
        project_id=uuid4(),
        name="Policy History Project",
        status="ACTIVE",
        created_at=CREATED_AT,
        updated_at=CREATED_AT,
    )


def build_policy(
    *,
    version: int,
    amount: int,
    decision: str = "REQUIRE_APPROVAL",
) -> Policy:
    return Policy.model_validate(
        {
            "id": "refund-limit",
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


def create_seeded_store(
    tmp_path,
) -> tuple[EvidenceStore, Project, Policy]:
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    initial_policy = build_policy(
        version=1,
        amount=500,
    )

    store.save_project(project)
    store.seed_project_policies(
        project_id=project.project_id,
        policies=[initial_policy],
        seeded_at=CREATED_AT,
    )

    return store, project, initial_policy


def test_initialize_creates_immutable_policy_versions_table(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        columns = connection.execute(
            "PRAGMA table_info(project_policy_versions)"
        ).fetchall()
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(project_policy_versions)"
        ).fetchall()
        indexes = connection.execute(
            "PRAGMA index_list(project_policy_versions)"
        ).fetchall()
        triggers = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'trigger'
            AND tbl_name = 'project_policy_versions'
            """
        ).fetchall()

    assert {
        column[1]
        for column in columns
    } == {
        "project_id",
        "policy_id",
        "version",
        "policy_json",
        "change_type",
        "source_version",
        "created_at",
    }
    assert {
        column[1]
        for column in columns
        if column[5] > 0
    } == {
        "project_id",
        "policy_id",
        "version",
    }
    assert len(foreign_keys) == 1
    assert foreign_keys[0][2] == "projects"
    assert {
        index[1]
        for index in indexes
    } >= {
        "idx_project_policy_versions_history",
    }
    assert {
        trigger[0]
        for trigger in triggers
    } == {
        "prevent_project_policy_version_update",
        "prevent_project_policy_version_delete",
    }


def test_initialize_backfills_existing_policy_once(
    tmp_path,
):
    database_path = tmp_path / "legacy.db"
    project = build_project()
    policy = build_policy(
        version=4,
        amount=250,
        decision="DENY",
    )
    updated_at = CREATED_AT + timedelta(hours=1)

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
            CREATE TABLE project_policies (
                project_id TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (project_id, policy_id),
                FOREIGN KEY (project_id)
                    REFERENCES projects(project_id)
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
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(project.project_id),
                project.name,
                project.status,
                project.created_at.isoformat(),
                project.updated_at.isoformat(),
            ),
        )
        connection.execute(
            """
            INSERT INTO project_policies (
                project_id,
                policy_id,
                version,
                policy_json,
                enabled,
                updated_at
            )
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (
                str(project.project_id),
                policy.id,
                policy.version,
                json.dumps(
                    policy.model_dump(mode="json"),
                    sort_keys=True,
                ),
                updated_at.isoformat(),
            ),
        )

    store = EvidenceStore(database_path)
    store.initialize()
    store.initialize()

    versions = store.list_project_policy_versions(
        project_id=project.project_id,
        policy_id=policy.id,
    )

    assert len(versions) == 1
    assert versions[0].policy == policy
    assert versions[0].change_type == "MIGRATED"
    assert versions[0].source_version is None
    assert versions[0].created_at == updated_at


def test_policy_changes_append_complete_versions(
    tmp_path,
):
    store, project, initial_policy = create_seeded_store(
        tmp_path
    )
    updated_policy = build_policy(
        version=2,
        amount=100,
        decision="DENY",
    )
    updated_at = CREATED_AT + timedelta(minutes=1)

    store.save_project_policy(
        project_id=project.project_id,
        policy=updated_policy,
        updated_at=updated_at,
    )

    versions = store.list_project_policy_versions(
        project_id=project.project_id,
        policy_id=initial_policy.id,
    )

    assert [
        version.version
        for version in versions
    ] == [2, 1]
    assert versions[0].policy == updated_policy
    assert versions[0].change_type == "UPDATED"
    assert versions[0].created_at == updated_at
    assert versions[1].policy == initial_policy
    assert versions[1].change_type == "CREATED"
    assert store.count_project_policy_versions(
        project_id=project.project_id,
        policy_id=initial_policy.id,
    ) == 2
    assert store.get_project_policy_version(
        project_id=project.project_id,
        policy_id=initial_policy.id,
        version=1,
    ) == versions[1]


def test_new_custom_policy_starts_created_history(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = build_project()
    policy = build_policy(
        version=1,
        amount=300,
    )
    store.save_project(project)

    store.save_project_policy(
        project_id=project.project_id,
        policy=policy,
        updated_at=CREATED_AT,
    )

    version = store.get_project_policy_version(
        project_id=project.project_id,
        policy_id=policy.id,
        version=1,
    )

    assert version is not None
    assert version.change_type == "CREATED"
    assert version.policy == policy


def test_policy_history_rejects_updates_and_deletes(
    tmp_path,
):
    store, project, policy = create_seeded_store(tmp_path)

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="policy versions are immutable",
        ):
            connection.execute(
                """
                UPDATE project_policy_versions
                SET change_type = 'UPDATED'
                WHERE project_id = ?
                AND policy_id = ?
                AND version = 1
                """,
                (
                    str(project.project_id),
                    policy.id,
                ),
            )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="policy versions are immutable",
        ):
            connection.execute(
                """
                DELETE FROM project_policy_versions
                WHERE project_id = ?
                AND policy_id = ?
                AND version = 1
                """,
                (
                    str(project.project_id),
                    policy.id,
                ),
            )

    assert store.count_project_policy_versions(
        project_id=project.project_id,
        policy_id=policy.id,
    ) == 1


def test_rollback_creates_new_version_without_mutating_history(
    tmp_path,
):
    store, project, initial_policy = create_seeded_store(
        tmp_path
    )
    second_policy = build_policy(
        version=2,
        amount=100,
        decision="DENY",
    )
    store.save_project_policy(
        project_id=project.project_id,
        policy=second_policy,
        updated_at=CREATED_AT + timedelta(minutes=1),
    )
    store.disable_project_policy(
        project_id=project.project_id,
        policy_id=initial_policy.id,
        updated_at=CREATED_AT + timedelta(minutes=2),
    )
    rolled_back_at = CREATED_AT + timedelta(minutes=3)

    configuration = store.rollback_project_policy(
        project_id=project.project_id,
        policy_id=initial_policy.id,
        source_version=1,
        updated_at=rolled_back_at,
    )
    versions = store.list_project_policy_versions(
        project_id=project.project_id,
        policy_id=initial_policy.id,
    )

    assert configuration.enabled is True
    assert configuration.updated_at == rolled_back_at
    assert configuration.policy.version == 3
    assert configuration.policy.conditions == (
        initial_policy.conditions
    )
    assert configuration.policy.decision == (
        initial_policy.decision
    )
    assert [
        version.version
        for version in versions
    ] == [3, 2, 1]
    assert versions[0].change_type == "ROLLBACK"
    assert versions[0].source_version == 1
    assert versions[0].policy == configuration.policy
    assert versions[1].policy == second_policy
    assert versions[1].change_type == "UPDATED"
    assert versions[2].policy == initial_policy
    assert versions[2].change_type == "CREATED"


def test_failed_history_write_rolls_back_active_policy(
    tmp_path,
    monkeypatch,
):
    store, project, initial_policy = create_seeded_store(
        tmp_path
    )
    second_policy = build_policy(
        version=2,
        amount=100,
        decision="DENY",
    )
    store.save_project_policy(
        project_id=project.project_id,
        policy=second_policy,
        updated_at=CREATED_AT + timedelta(minutes=1),
    )

    def fail_history_insert(**_):
        raise sqlite3.IntegrityError(
            "simulated history failure"
        )

    monkeypatch.setattr(
        store.policies,
        "insert_version",
        fail_history_insert,
    )

    with pytest.raises(
        sqlite3.IntegrityError,
        match="simulated history failure",
    ):
        store.rollback_project_policy(
            project_id=project.project_id,
            policy_id=initial_policy.id,
            source_version=1,
            updated_at=CREATED_AT + timedelta(minutes=2),
        )

    current = store.get_project_policy_configuration(
        project_id=project.project_id,
        policy_id=initial_policy.id,
    )

    assert current is not None
    assert current.policy == second_policy
    assert store.count_project_policy_versions(
        project_id=project.project_id,
        policy_id=initial_policy.id,
    ) == 2


def test_policy_history_is_scoped_to_project(
    tmp_path,
):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    first_project = build_project()
    second_project = build_project()
    initial_policy = build_policy(
        version=1,
        amount=500,
    )

    store.save_project(first_project)
    store.save_project(second_project)
    store.seed_project_policies(
        project_id=first_project.project_id,
        policies=[initial_policy],
        seeded_at=CREATED_AT,
    )
    store.seed_project_policies(
        project_id=second_project.project_id,
        policies=[initial_policy],
        seeded_at=CREATED_AT,
    )
    store.save_project_policy(
        project_id=first_project.project_id,
        policy=build_policy(
            version=2,
            amount=100,
            decision="DENY",
        ),
        updated_at=CREATED_AT + timedelta(minutes=1),
    )

    assert store.count_project_policy_versions(
        project_id=first_project.project_id,
        policy_id=initial_policy.id,
    ) == 2
    assert store.count_project_policy_versions(
        project_id=second_project.project_id,
        policy_id=initial_policy.id,
    ) == 1
    assert store.get_project_policy_version(
        project_id=second_project.project_id,
        policy_id=initial_policy.id,
        version=2,
    ) is None

    with pytest.raises(PolicyVersionNotFoundError):
        store.rollback_project_policy(
            project_id=second_project.project_id,
            policy_id=initial_policy.id,
            source_version=2,
            updated_at=CREATED_AT + timedelta(minutes=2),
        )


def test_rollback_rejects_missing_and_current_versions(
    tmp_path,
):
    store, project, policy = create_seeded_store(tmp_path)

    with pytest.raises(
        PolicyVersionNotFoundError
    ) as missing_error:
        store.rollback_project_policy(
            project_id=project.project_id,
            policy_id=policy.id,
            source_version=99,
            updated_at=CREATED_AT + timedelta(minutes=1),
        )

    assert missing_error.value.version == 99

    with pytest.raises(
        PolicyVersionAlreadyCurrentError
    ) as current_error:
        store.rollback_project_policy(
            project_id=project.project_id,
            policy_id=policy.id,
            source_version=1,
            updated_at=CREATED_AT + timedelta(minutes=1),
        )

    assert current_error.value.version == 1


def test_policy_history_pagination_uses_descending_versions(
    tmp_path,
):
    store, project, policy = create_seeded_store(tmp_path)
    store.save_project_policy(
        project_id=project.project_id,
        policy=build_policy(
            version=2,
            amount=300,
        ),
        updated_at=CREATED_AT + timedelta(minutes=1),
    )
    store.save_project_policy(
        project_id=project.project_id,
        policy=build_policy(
            version=3,
            amount=200,
        ),
        updated_at=CREATED_AT + timedelta(minutes=2),
    )

    page = store.list_project_policy_versions(
        project_id=project.project_id,
        policy_id=policy.id,
        limit=1,
        offset=1,
    )

    assert [entry.version for entry in page] == [2]
    assert store.count_project_policy_versions(
        project_id=project.project_id,
        policy_id=policy.id,
    ) == 3

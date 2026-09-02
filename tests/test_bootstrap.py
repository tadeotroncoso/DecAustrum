import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.api_keys import (
    generate_project_api_key,
    hash_api_key,
)
from app.bootstrap import (
    DEFAULT_PROJECT_ID,
    bootstrap_default_project,
)
from app.evidence_store import EvidenceStore
from app.project_models import Project

BOOTSTRAP_TIME = datetime(
    2026,
    8,
    28,
    12,
    0,
    tzinfo=timezone.utc,
)


def test_bootstrap_creates_default_project_and_key(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    api_key = generate_project_api_key()

    project = bootstrap_default_project(
        store=store,
        api_key=api_key,
        created_at=BOOTSTRAP_TIME,
    )

    assert project.project_id == DEFAULT_PROJECT_ID
    assert project.name == "Default Project"
    assert project.status == "ACTIVE"
    assert project.created_at == BOOTSTRAP_TIME

    authenticated_project = (
        store.get_active_project_by_api_key_hash(
            hash_api_key(api_key)
        )
    )

    assert authenticated_project == project
    principal = store.get_active_api_key_principal_by_hash(
        hash_api_key(api_key)
    )
    assert principal is not None
    assert principal.role == "RUNTIME"


def test_bootstrap_is_idempotent(tmp_path):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    api_key = generate_project_api_key()

    first_project = bootstrap_default_project(
        store=store,
        api_key=api_key,
        created_at=BOOTSTRAP_TIME,
    )

    second_project = bootstrap_default_project(
        store=store,
        api_key=api_key,
        created_at=BOOTSTRAP_TIME,
    )

    assert second_project == first_project

    with sqlite3.connect(database_path) as connection:
        project_count = connection.execute(
            "SELECT COUNT(*) FROM projects"
        ).fetchone()[0]

        api_key_count = connection.execute(
            "SELECT COUNT(*) FROM project_api_keys"
        ).fetchone()[0]

    assert project_count == 1
    assert api_key_count == 1


def test_bootstrap_adds_new_key_without_revoking_previous_key(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    first_api_key = generate_project_api_key()
    second_api_key = generate_project_api_key()

    project = bootstrap_default_project(
        store=store,
        api_key=first_api_key,
        created_at=BOOTSTRAP_TIME,
    )

    rotated_project = bootstrap_default_project(
        store=store,
        api_key=second_api_key,
        created_at=BOOTSTRAP_TIME,
    )

    assert rotated_project == project

    assert (
        store.get_active_project_by_api_key_hash(
            hash_api_key(first_api_key)
        )
        == project
    )

    assert (
        store.get_active_project_by_api_key_hash(
            hash_api_key(second_api_key)
        )
        == project
    )

    with sqlite3.connect(database_path) as connection:
        api_key_count = connection.execute(
            "SELECT COUNT(*) FROM project_api_keys"
        ).fetchone()[0]

    assert api_key_count == 2


def test_explicit_revocation_completes_bootstrap_key_rotation(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    first_api_key = generate_project_api_key()
    second_api_key = generate_project_api_key()
    project = bootstrap_default_project(
        store=store,
        api_key=first_api_key,
        created_at=BOOTSTRAP_TIME,
    )
    first_principal = store.get_active_api_key_principal_by_hash(
        hash_api_key(first_api_key)
    )
    assert first_principal is not None
    bootstrap_default_project(
        store=store,
        api_key=second_api_key,
        created_at=BOOTSTRAP_TIME + timedelta(minutes=1),
    )

    store.revoke_project_api_key(
        project_id=project.project_id,
        api_key_id=first_principal.api_key_id,
        revoked_at=BOOTSTRAP_TIME + timedelta(minutes=2),
    )
    bootstrap_default_project(
        store=store,
        api_key=second_api_key,
        created_at=BOOTSTRAP_TIME + timedelta(minutes=3),
    )

    assert store.get_active_project_by_api_key_hash(
        hash_api_key(first_api_key)
    ) is None
    assert store.get_active_project_by_api_key_hash(
        hash_api_key(second_api_key)
    ) == project


def test_bootstrap_rejects_disabled_default_project(
    tmp_path,
):
    database_path = tmp_path / "test.db"
    store = EvidenceStore(database_path)
    store.initialize()

    disabled_project = Project(
        project_id=DEFAULT_PROJECT_ID,
        name="Default Project",
        status="DISABLED",
        created_at=BOOTSTRAP_TIME,
    )

    store.save_project(disabled_project)

    with pytest.raises(
        RuntimeError,
        match="Default project is disabled.",
    ):
        bootstrap_default_project(
            store=store,
            api_key=generate_project_api_key(),
            created_at=BOOTSTRAP_TIME,
        )

    with sqlite3.connect(database_path) as connection:
        api_key_count = connection.execute(
            "SELECT COUNT(*) FROM project_api_keys"
        ).fetchone()[0]

    assert api_key_count == 0

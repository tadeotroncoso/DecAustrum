import sqlite3
from pathlib import Path

from app.project_models import DEFAULT_PROJECT_ID


CREATE_DECISIONS_TABLE = """
CREATE TABLE IF NOT EXISTS authorization_decisions (
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

CREATE_DECISION_INTEGRITY_RECORDS_TABLE = """
CREATE TABLE IF NOT EXISTS decision_integrity_records (
    decision_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL CHECK (
        sequence_number >= 1
    ),
    previous_hash TEXT,
    payload_hash TEXT NOT NULL CHECK (
        length(payload_hash) = 64
        AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    record_hash TEXT NOT NULL UNIQUE CHECK (
        length(record_hash) = 64
        AND record_hash NOT GLOB '*[^0-9a-f]*'
    ),
    algorithm TEXT NOT NULL CHECK (
        algorithm = 'SHA-256'
    ),
    schema_version INTEGER NOT NULL CHECK (
        schema_version = 1
    ),
    created_at TEXT NOT NULL,
    UNIQUE (project_id, sequence_number),
    FOREIGN KEY (decision_id)
        REFERENCES authorization_decisions(decision_id),
    CHECK (
        (
            sequence_number = 1
            AND previous_hash IS NULL
        )
        OR (
            sequence_number > 1
            AND previous_hash IS NOT NULL
            AND length(previous_hash) = 64
            AND previous_hash NOT GLOB '*[^0-9a-f]*'
        )
    )
)
"""

CREATE_DECISION_INTEGRITY_RECORDS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_decision_integrity_project_chain
ON decision_integrity_records (
    project_id,
    sequence_number DESC
)
"""

CREATE_DECISION_INTEGRITY_PROJECT_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS enforce_decision_integrity_project
BEFORE INSERT ON decision_integrity_records
WHEN NOT EXISTS (
    SELECT 1
    FROM authorization_decisions
    WHERE decision_id = NEW.decision_id
    AND project_id = NEW.project_id
)
BEGIN
    SELECT RAISE(
        ABORT,
        'integrity project must match decision project'
    );
END
"""

CREATE_DECISIONS_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_authorization_decision_update
BEFORE UPDATE ON authorization_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'authorization decisions are immutable'
    );
END
"""

CREATE_DECISIONS_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_authorization_decision_delete
BEFORE DELETE ON authorization_decisions
BEGIN
    SELECT RAISE(
        ABORT,
        'authorization decisions are immutable'
    );
END
"""

CREATE_DECISION_INTEGRITY_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_decision_integrity_update
BEFORE UPDATE ON decision_integrity_records
BEGIN
    SELECT RAISE(
        ABORT,
        'decision integrity records are immutable'
    );
END
"""

CREATE_DECISION_INTEGRITY_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_decision_integrity_delete
BEFORE DELETE ON decision_integrity_records
BEGIN
    SELECT RAISE(
        ABORT,
        'decision integrity records are immutable'
    );
END
"""

CREATE_APPROVAL_REQUESTS_TABLE = """
CREATE TABLE IF NOT EXISTS approval_requests (
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

CREATE_IDEMPOTENCY_RECORDS_TABLE = """
CREATE TABLE IF NOT EXISTS idempotency_records (
    project_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    decision_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, idempotency_key),
    FOREIGN KEY (decision_id)
        REFERENCES authorization_decisions(decision_id)
)
"""

CREATE_PROJECTS_TABLE = """
CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('ACTIVE', 'DISABLED')
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
)
"""

CREATE_PROJECT_API_KEYS_TABLE = """
CREATE TABLE IF NOT EXISTS project_api_keys (
    api_key_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id)
)
"""

CREATE_PROJECT_POLICIES_TABLE = """
CREATE TABLE IF NOT EXISTS project_policies (
    project_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    policy_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (
        enabled IN (0, 1)
    ),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, policy_id),
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id)
)
"""

CREATE_PROJECT_POLICIES_INDEX = """
CREATE INDEX IF NOT EXISTS idx_project_policies_active
ON project_policies (project_id, enabled, policy_id)
"""

CREATE_PROJECT_POLICY_VERSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS project_policy_versions (
    project_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    policy_json TEXT NOT NULL,
    change_type TEXT NOT NULL CHECK (
        change_type IN (
            'CREATED',
            'UPDATED',
            'ROLLBACK',
            'MIGRATED'
        )
    ),
    source_version INTEGER,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, policy_id, version),
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id),
    CHECK (
        (
            change_type = 'ROLLBACK'
            AND source_version IS NOT NULL
        )
        OR (
            change_type != 'ROLLBACK'
            AND source_version IS NULL
        )
    )
)
"""

CREATE_PROJECT_POLICY_VERSIONS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_project_policy_versions_history
ON project_policy_versions (
    project_id,
    policy_id,
    version DESC
)
"""

CREATE_PROJECT_POLICY_VERSIONS_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_project_policy_version_update
BEFORE UPDATE ON project_policy_versions
BEGIN
    SELECT RAISE(
        ABORT,
        'project policy versions are immutable'
    );
END
"""

CREATE_PROJECT_POLICY_VERSIONS_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_project_policy_version_delete
BEFORE DELETE ON project_policy_versions
BEGIN
    SELECT RAISE(
        ABORT,
        'project policy versions are immutable'
    );
END
"""


class SQLiteDatabase:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _migrate_projects_table(
        connection: sqlite3.Connection,
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(projects)"
        ).fetchall()

        column_names = {
            column[1]
            for column in columns
        }

        if "updated_at" in column_names:
            return

        connection.execute(
            """
            ALTER TABLE projects
            ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''
            """
        )

        connection.execute(
            """
            UPDATE projects
            SET updated_at = created_at
            WHERE updated_at = ''
            """
        )

    @staticmethod
    def _migrate_decisions_table(
        connection: sqlite3.Connection,
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(authorization_decisions)"
        ).fetchall()

        column_names = {
            column[1]
            for column in columns
        }

        if "trace_json" not in column_names:
            connection.execute(
                """
                ALTER TABLE authorization_decisions
                ADD COLUMN trace_json
                TEXT NOT NULL DEFAULT '[]'
                """
            )

        if "project_id" not in column_names:
            connection.execute(
                f"""
                ALTER TABLE authorization_decisions
                ADD COLUMN project_id TEXT NOT NULL
                DEFAULT '{DEFAULT_PROJECT_ID}'
                """
            )

    @staticmethod
    def _migrate_decision_integrity_records_table(
        connection: sqlite3.Connection,
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(decision_integrity_records)"
        ).fetchall()

        column_names = {
            column[1]
            for column in columns
        }

        if "schema_version" in column_names:
            return

        connection.execute(
            """
            ALTER TABLE decision_integrity_records
            ADD COLUMN schema_version
            INTEGER NOT NULL DEFAULT 1
            CHECK (schema_version = 1)
            """
        )

    @staticmethod
    def _migrate_idempotency_records_table(
        connection: sqlite3.Connection,
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(idempotency_records)"
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

        expected_primary_key = {
            "project_id",
            "idempotency_key",
        }

        if (
            "project_id" in column_names
            and primary_key_columns == expected_primary_key
        ):
            return

        connection.execute(
            """
            ALTER TABLE idempotency_records
            RENAME TO legacy_idempotency_records
            """
        )

        connection.execute(
            CREATE_IDEMPOTENCY_RECORDS_TABLE
        )

        connection.execute(
            """
            INSERT INTO idempotency_records (
                project_id,
                idempotency_key,
                request_fingerprint,
                decision_id,
                created_at
            )
            SELECT
                authorization_decisions.project_id,
                legacy_idempotency_records.idempotency_key,
                legacy_idempotency_records.request_fingerprint,
                legacy_idempotency_records.decision_id,
                legacy_idempotency_records.created_at
            FROM legacy_idempotency_records
            JOIN authorization_decisions
                ON authorization_decisions.decision_id
                = legacy_idempotency_records.decision_id
            """
        )

        connection.execute(
            "DROP TABLE legacy_idempotency_records"
        )

    @staticmethod
    def _backfill_project_policy_versions(
        connection: sqlite3.Connection,
    ) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO project_policy_versions (
                project_id,
                policy_id,
                version,
                policy_json,
                change_type,
                source_version,
                created_at
            )
            SELECT
                project_id,
                policy_id,
                version,
                policy_json,
                'MIGRATED',
                NULL,
                updated_at
            FROM project_policies
            """
        )

    def initialize(self) -> None:
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.connect() as connection:
            connection.execute(CREATE_PROJECTS_TABLE)
            self._migrate_projects_table(connection)
            connection.execute(CREATE_PROJECT_API_KEYS_TABLE)
            connection.execute(CREATE_PROJECT_POLICIES_TABLE)
            connection.execute(CREATE_PROJECT_POLICIES_INDEX)
            connection.execute(
                CREATE_PROJECT_POLICY_VERSIONS_TABLE
            )
            connection.execute(
                CREATE_PROJECT_POLICY_VERSIONS_INDEX
            )
            self._backfill_project_policy_versions(connection)
            connection.execute(
                CREATE_PROJECT_POLICY_VERSIONS_UPDATE_TRIGGER
            )
            connection.execute(
                CREATE_PROJECT_POLICY_VERSIONS_DELETE_TRIGGER
            )
            connection.execute(CREATE_DECISIONS_TABLE)
            self._migrate_decisions_table(connection)
            connection.execute(
                CREATE_DECISION_INTEGRITY_RECORDS_TABLE
            )
            self._migrate_decision_integrity_records_table(
                connection
            )
            connection.execute(
                CREATE_DECISION_INTEGRITY_RECORDS_INDEX
            )
            connection.execute(
                CREATE_DECISION_INTEGRITY_PROJECT_TRIGGER
            )
            connection.execute(CREATE_DECISIONS_UPDATE_TRIGGER)
            connection.execute(CREATE_DECISIONS_DELETE_TRIGGER)
            connection.execute(
                CREATE_DECISION_INTEGRITY_UPDATE_TRIGGER
            )
            connection.execute(
                CREATE_DECISION_INTEGRITY_DELETE_TRIGGER
            )
            connection.execute(CREATE_APPROVAL_REQUESTS_TABLE)
            connection.execute(CREATE_IDEMPOTENCY_RECORDS_TABLE)

            self._migrate_idempotency_records_table(
                connection
            )

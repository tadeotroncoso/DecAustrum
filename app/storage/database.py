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

CREATE_DECISIONS_PROJECT_TIME_INDEX = """
CREATE INDEX IF NOT EXISTS idx_decisions_project_time
ON authorization_decisions (
    project_id,
    evaluated_at DESC,
    decision_id DESC
)
"""

CREATE_DECISIONS_PROJECT_DECISION_INDEX = """
CREATE INDEX IF NOT EXISTS idx_decisions_project_decision
ON authorization_decisions (
    project_id,
    decision,
    evaluated_at DESC
)
"""

CREATE_DECISIONS_PROJECT_AGENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_decisions_project_agent
ON authorization_decisions (
    project_id,
    agent,
    evaluated_at DESC
)
"""

CREATE_DECISIONS_PROJECT_ACTION_INDEX = """
CREATE INDEX IF NOT EXISTS idx_decisions_project_action
ON authorization_decisions (
    project_id,
    action,
    evaluated_at DESC
)
"""

CREATE_DECISIONS_PROJECT_POLICY_INDEX = """
CREATE INDEX IF NOT EXISTS idx_decisions_project_policy
ON authorization_decisions (
    project_id,
    policy_id,
    evaluated_at DESC
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
        status IN (
            'PENDING',
            'APPROVED',
            'REJECTED',
            'EXPIRED'
        )
    ),
    requested_at TEXT NOT NULL,
    expires_at TEXT,
    resolved_at TEXT,
    resolved_by TEXT,
    FOREIGN KEY (decision_id)
        REFERENCES authorization_decisions(decision_id),
    CHECK (
        (
            status = 'PENDING'
            AND resolved_at IS NULL
            AND resolved_by IS NULL
        )
        OR (
            status != 'PENDING'
            AND resolved_at IS NOT NULL
            AND resolved_by IS NOT NULL
        )
    ),
    CHECK (
        expires_at IS NULL
        OR expires_at > requested_at
    )
)
"""

CREATE_APPROVAL_REQUESTS_STATUS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_approval_requests_status
ON approval_requests (status, requested_at DESC)
"""

CREATE_APPROVAL_REQUESTS_EXPIRY_INDEX = """
CREATE INDEX IF NOT EXISTS idx_approval_requests_expiry
ON approval_requests (status, expires_at)
"""

CREATE_APPROVAL_LIFECYCLE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS protect_approval_lifecycle
BEFORE UPDATE ON approval_requests
WHEN
    OLD.decision_id IS NOT NEW.decision_id
    OR OLD.requested_at IS NOT NEW.requested_at
    OR OLD.expires_at IS NOT NEW.expires_at
    OR OLD.status != 'PENDING'
    OR NEW.status NOT IN ('APPROVED', 'REJECTED', 'EXPIRED')
BEGIN
    SELECT RAISE(
        ABORT,
        'approval lifecycle is immutable'
    );
END
"""

CREATE_APPROVAL_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_approval_delete
BEFORE DELETE ON approval_requests
BEGIN
    SELECT RAISE(
        ABORT,
        'approval requests cannot be deleted'
    );
END
"""

CREATE_EXECUTION_GRANTS_TABLE = """
CREATE TABLE IF NOT EXISTS execution_grants (
    grant_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL UNIQUE,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('ACTIVE', 'CONSUMED', 'EXPIRED')
    ),
    request_fingerprint TEXT NOT NULL CHECK (
        length(request_fingerprint) = 64
        AND request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    token_hash TEXT NOT NULL UNIQUE CHECK (
        length(token_hash) = 64
        AND token_hash NOT GLOB '*[^0-9a-f]*'
    ),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    consumed_by TEXT,
    FOREIGN KEY (decision_id)
        REFERENCES authorization_decisions(decision_id),
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id),
    CHECK (expires_at > issued_at),
    CHECK (
        (
            status = 'CONSUMED'
            AND consumed_at IS NOT NULL
            AND consumed_by IS NOT NULL
        )
        OR (
            status IN ('ACTIVE', 'EXPIRED')
            AND consumed_at IS NULL
            AND consumed_by IS NULL
        )
    )
)
"""

CREATE_EXECUTION_GRANTS_PROJECT_STATUS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_execution_grants_project_status
ON execution_grants (project_id, status, expires_at)
"""

CREATE_EXECUTION_GRANT_SCOPE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS enforce_execution_grant_scope
BEFORE INSERT ON execution_grants
WHEN
    NEW.status != 'ACTIVE'
    OR NOT EXISTS (
        SELECT 1
        FROM authorization_decisions
        WHERE decision_id = NEW.decision_id
        AND project_id = NEW.project_id
        AND decision = 'REQUIRE_APPROVAL'
    )
    OR NOT EXISTS (
        SELECT 1
        FROM approval_requests
        WHERE decision_id = NEW.decision_id
        AND status = 'PENDING'
        AND NEW.issued_at >= requested_at
        AND (
            expires_at IS NULL
            OR NEW.issued_at < expires_at
        )
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'execution grant requires a matching pending approval'
    );
END
"""

CREATE_APPROVAL_GRANT_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS require_execution_grant_for_approval
BEFORE UPDATE OF status ON approval_requests
WHEN
    OLD.status = 'PENDING'
    AND NEW.status = 'APPROVED'
    AND NOT EXISTS (
        SELECT 1
        FROM execution_grants
        WHERE decision_id = NEW.decision_id
        AND status = 'ACTIVE'
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'approved request requires an active execution grant'
    );
END
"""

CREATE_EXECUTION_GRANT_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS protect_execution_grant_lifecycle
BEFORE UPDATE ON execution_grants
WHEN
    OLD.grant_id IS NOT NEW.grant_id
    OR OLD.decision_id IS NOT NEW.decision_id
    OR OLD.project_id IS NOT NEW.project_id
    OR OLD.request_fingerprint IS NOT NEW.request_fingerprint
    OR OLD.token_hash IS NOT NEW.token_hash
    OR OLD.issued_at IS NOT NEW.issued_at
    OR OLD.expires_at IS NOT NEW.expires_at
    OR OLD.status != 'ACTIVE'
    OR NEW.status NOT IN ('CONSUMED', 'EXPIRED')
BEGIN
    SELECT RAISE(
        ABORT,
        'execution grant lifecycle is immutable'
    );
END
"""

CREATE_EXECUTION_GRANT_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_execution_grant_delete
BEFORE DELETE ON execution_grants
BEGIN
    SELECT RAISE(
        ABORT,
        'execution grants cannot be deleted'
    );
END
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
    role TEXT NOT NULL CHECK (
        role IN ('RUNTIME', 'REVIEWER')
    ),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id)
)
"""

CREATE_WEBHOOK_SUBSCRIPTIONS_TABLE = """
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    subscription_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    url TEXT NOT NULL,
    event_types_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('ACTIVE', 'DISABLED')
    ),
    secret_version INTEGER NOT NULL CHECK (
        secret_version >= 1
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    disabled_at TEXT,
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id),
    CHECK (
        (
            status = 'ACTIVE'
            AND disabled_at IS NULL
        )
        OR (
            status = 'DISABLED'
            AND disabled_at IS NOT NULL
        )
    )
)
"""

CREATE_WEBHOOK_SUBSCRIPTIONS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_project
ON webhook_subscriptions (
    project_id,
    status,
    created_at DESC
)
"""

CREATE_WEBHOOK_SUBSCRIPTIONS_IDENTITY_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS protect_webhook_subscription_identity
BEFORE UPDATE ON webhook_subscriptions
WHEN
    OLD.subscription_id != NEW.subscription_id
    OR OLD.project_id != NEW.project_id
    OR OLD.url != NEW.url
    OR OLD.event_types_json != NEW.event_types_json
    OR OLD.created_at != NEW.created_at
BEGIN
    SELECT RAISE(
        ABORT,
        'webhook subscription identity is immutable'
    );
END
"""

CREATE_WEBHOOK_SUBSCRIPTIONS_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_webhook_subscription_delete
BEFORE DELETE ON webhook_subscriptions
BEGIN
    SELECT RAISE(
        ABORT,
        'webhook subscriptions cannot be deleted'
    );
END
"""

CREATE_WEBHOOK_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'authorization.created',
            'approval.requested',
            'approval.resolved',
            'approval.expired',
            'execution_grant.issued',
            'execution_grant.consumed',
            'execution_grant.expired',
            'project.created',
            'project.status_changed',
            'api_key.created',
            'api_key.revoked',
            'policy.created',
            'policy.updated',
            'policy.disabled',
            'policy.rolled_back',
            'webhook.subscription.created',
            'webhook.subscription.disabled',
            'webhook.subscription.secret_rotated',
            'webhook.delivery.redelivery_requested'
        )
    ),
    occurred_at TEXT NOT NULL,
    resource_type TEXT NOT NULL CHECK (
        resource_type IN (
            'AUTHORIZATION_DECISION',
            'APPROVAL',
            'EXECUTION_GRANT',
            'PROJECT',
            'API_KEY',
            'POLICY',
            'WEBHOOK_SUBSCRIPTION',
            'WEBHOOK_DELIVERY'
        )
    ),
    resource_id TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (
        schema_version = 1
    ),
    payload_json TEXT NOT NULL,
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id)
)
"""

CREATE_WEBHOOK_EVENTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_webhook_events_project
ON webhook_events (
    project_id,
    occurred_at DESC,
    event_id DESC
)
"""

CREATE_WEBHOOK_EVENTS_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_webhook_event_update
BEFORE UPDATE ON webhook_events
BEGIN
    SELECT RAISE(ABORT, 'webhook events are immutable');
END
"""

CREATE_WEBHOOK_EVENTS_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_webhook_event_delete
BEFORE DELETE ON webhook_events
BEGIN
    SELECT RAISE(ABORT, 'webhook events are immutable');
END
"""

CREATE_WEBHOOK_DELIVERIES_TABLE = """
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    delivery_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN (
            'PENDING',
            'PROCESSING',
            'RETRY_SCHEDULED',
            'DELIVERED',
            'DEAD_LETTER',
            'CANCELLED'
        )
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (
        attempt_count >= 0
    ),
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (
        failure_count >= 0
    ),
    redelivery_count INTEGER NOT NULL DEFAULT 0 CHECK (
        redelivery_count >= 0
    ),
    next_attempt_at TEXT,
    lease_expires_at TEXT,
    delivered_at TEXT,
    last_attempt_at TEXT,
    last_status_code INTEGER CHECK (
        last_status_code IS NULL
        OR last_status_code BETWEEN 100 AND 599
    ),
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (event_id, subscription_id),
    FOREIGN KEY (event_id)
        REFERENCES webhook_events(event_id),
    FOREIGN KEY (subscription_id)
        REFERENCES webhook_subscriptions(subscription_id),
    FOREIGN KEY (project_id)
        REFERENCES projects(project_id)
)
"""

CREATE_WEBHOOK_DELIVERIES_DUE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
ON webhook_deliveries (
    status,
    next_attempt_at,
    lease_expires_at
)
"""

CREATE_WEBHOOK_DELIVERIES_PROJECT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_project
ON webhook_deliveries (
    project_id,
    created_at DESC,
    delivery_id DESC
)
"""

CREATE_WEBHOOK_DELIVERY_PROJECT_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS enforce_webhook_delivery_project
BEFORE INSERT ON webhook_deliveries
WHEN
    NOT EXISTS (
        SELECT 1
        FROM webhook_events
        WHERE event_id = NEW.event_id
        AND project_id = NEW.project_id
    )
    OR NOT EXISTS (
        SELECT 1
        FROM webhook_subscriptions
        WHERE subscription_id = NEW.subscription_id
        AND project_id = NEW.project_id
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'webhook delivery project must match event and subscription'
    );
END
"""

CREATE_WEBHOOK_DELIVERY_IDENTITY_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS protect_webhook_delivery_identity
BEFORE UPDATE ON webhook_deliveries
WHEN
    OLD.delivery_id != NEW.delivery_id
    OR OLD.event_id != NEW.event_id
    OR OLD.subscription_id != NEW.subscription_id
    OR OLD.project_id != NEW.project_id
    OR OLD.created_at != NEW.created_at
BEGIN
    SELECT RAISE(
        ABORT,
        'webhook delivery identity is immutable'
    );
END
"""

CREATE_WEBHOOK_DELIVERIES_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_webhook_delivery_delete
BEFORE DELETE ON webhook_deliveries
BEGIN
    SELECT RAISE(ABORT, 'webhook deliveries cannot be deleted');
END
"""

CREATE_WEBHOOK_DELIVERY_ATTEMPTS_TABLE = """
CREATE TABLE IF NOT EXISTS webhook_delivery_attempts (
    attempt_id TEXT PRIMARY KEY,
    delivery_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK (
        attempt_number >= 1
    ),
    attempted_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (
        outcome IN (
            'SUCCESS',
            'HTTP_ERROR',
            'NETWORK_ERROR'
        )
    ),
    status_code INTEGER CHECK (
        status_code IS NULL
        OR status_code BETWEEN 100 AND 599
    ),
    error TEXT,
    UNIQUE (delivery_id, attempt_number),
    FOREIGN KEY (delivery_id)
        REFERENCES webhook_deliveries(delivery_id)
)
"""

CREATE_WEBHOOK_DELIVERY_ATTEMPTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_attempts_delivery
ON webhook_delivery_attempts (
    delivery_id,
    attempt_number DESC
)
"""

CREATE_WEBHOOK_DELIVERY_ATTEMPTS_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_webhook_attempt_update
BEFORE UPDATE ON webhook_delivery_attempts
BEGIN
    SELECT RAISE(ABORT, 'webhook attempts are immutable');
END
"""

CREATE_WEBHOOK_DELIVERY_ATTEMPTS_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_webhook_attempt_delete
BEFORE DELETE ON webhook_delivery_attempts
BEGIN
    SELECT RAISE(ABORT, 'webhook attempts are immutable');
END
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

CREATE_ADMINISTRATIVE_AUDIT_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS administrative_audit_events (
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
            'APPROVAL_RESOLVED',
            'APPROVAL_EXPIRED',
            'EXECUTION_GRANT_ISSUED',
            'EXECUTION_GRANT_CONSUMED',
            'EXECUTION_GRANT_EXPIRED',
            'WEBHOOK_SUBSCRIPTION_CREATED',
            'WEBHOOK_SUBSCRIPTION_DISABLED',
            'WEBHOOK_SECRET_ROTATED',
            'WEBHOOK_REDELIVERY_REQUESTED'
        )
    ),
    resource_type TEXT NOT NULL CHECK (
        resource_type IN (
            'PROJECT',
            'API_KEY',
            'POLICY',
            'APPROVAL',
            'EXECUTION_GRANT',
            'WEBHOOK_SUBSCRIPTION',
            'WEBHOOK_DELIVERY'
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

CREATE_ADMINISTRATIVE_AUDIT_EVENTS_INDEX = """
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_occurred
ON administrative_audit_events (
    occurred_at DESC,
    event_id DESC
)
"""

CREATE_ADMINISTRATIVE_AUDIT_PROJECT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_admin_audit_events_project
ON administrative_audit_events (
    project_id,
    occurred_at DESC
)
"""

CREATE_ADMINISTRATIVE_AUDIT_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_admin_audit_event_update
BEFORE UPDATE ON administrative_audit_events
BEGIN
    SELECT RAISE(
        ABORT,
        'administrative audit events are immutable'
    );
END
"""

CREATE_ADMINISTRATIVE_AUDIT_DELETE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS prevent_admin_audit_event_delete
BEFORE DELETE ON administrative_audit_events
BEGIN
    SELECT RAISE(
        ABORT,
        'administrative audit events are immutable'
    );
END
"""


class SQLiteDatabase:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=5.0,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection

    def check_readiness(self) -> bool:
        if not self.database_path.is_file():
            return False

        required_tables = {
            "projects",
            "authorization_decisions",
            "decision_integrity_records",
            "approval_requests",
            "execution_grants",
        }

        with self.connect() as connection:
            if connection.execute("SELECT 1").fetchone() != (1,):
                return False

            foreign_keys = connection.execute(
                "PRAGMA foreign_keys"
            ).fetchone()
            journal_mode = connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()
            rows = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()

        table_names = {row[0] for row in rows}
        return (
            foreign_keys == (1,)
            and journal_mode is not None
            and str(journal_mode[0]).lower() == "wal"
            and required_tables <= table_names
        )

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
    def _migrate_project_api_keys_table(
        connection: sqlite3.Connection,
    ) -> None:
        columns = connection.execute(
            "PRAGMA table_info(project_api_keys)"
        ).fetchall()
        column_names = {column[1] for column in columns}

        if "role" in column_names:
            return

        connection.execute(
            """
            ALTER TABLE project_api_keys
            ADD COLUMN role TEXT NOT NULL DEFAULT 'RUNTIME'
            CHECK (role IN ('RUNTIME', 'REVIEWER'))
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
    def _migrate_approval_requests_table(
        connection: sqlite3.Connection,
    ) -> None:
        row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'approval_requests'
            """
        ).fetchone()

        columns = connection.execute(
            "PRAGMA table_info(approval_requests)"
        ).fetchall()
        column_names = {column[1] for column in columns}

        if (
            row is None
            or (
                "expires_at" in column_names
                and "EXPIRED" in row[0]
            )
        ):
            return

        expires_at_expression = (
            "expires_at"
            if "expires_at" in column_names
            else "NULL"
        )
        for trigger_name in (
            "protect_approval_lifecycle",
            "prevent_approval_delete",
            "require_execution_grant_for_approval",
        ):
            connection.execute(
                f"DROP TRIGGER IF EXISTS {trigger_name}"
            )
        connection.execute(
            "DROP INDEX IF EXISTS idx_approval_requests_status"
        )
        connection.execute(
            "DROP INDEX IF EXISTS idx_approval_requests_expiry"
        )
        connection.execute(
            """
            ALTER TABLE approval_requests
            RENAME TO legacy_approval_requests
            """
        )
        connection.execute(CREATE_APPROVAL_REQUESTS_TABLE)
        connection.execute(
            f"""
            INSERT INTO approval_requests (
                decision_id,
                status,
                requested_at,
                expires_at,
                resolved_at,
                resolved_by
            )
            SELECT
                decision_id,
                status,
                requested_at,
                {expires_at_expression},
                resolved_at,
                resolved_by
            FROM legacy_approval_requests
            """  # nosec B608
        )
        connection.execute(
            "DROP TABLE legacy_approval_requests"
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
    def _migrate_administrative_audit_events_table(
        connection: sqlite3.Connection,
    ) -> None:
        row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'administrative_audit_events'
            """
        ).fetchone()

        if (
            row is None
            or "EXECUTION_GRANT_CONSUMED" in row[0]
        ):
            return

        connection.execute(
            "DROP TRIGGER IF EXISTS "
            "prevent_admin_audit_event_update"
        )
        connection.execute(
            "DROP TRIGGER IF EXISTS "
            "prevent_admin_audit_event_delete"
        )
        connection.execute(
            "DROP INDEX IF EXISTS "
            "idx_admin_audit_events_occurred"
        )
        connection.execute(
            "DROP INDEX IF EXISTS "
            "idx_admin_audit_events_project"
        )
        connection.execute(
            """
            ALTER TABLE administrative_audit_events
            RENAME TO legacy_administrative_audit_events
            """
        )
        connection.execute(
            CREATE_ADMINISTRATIVE_AUDIT_EVENTS_TABLE
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
                reason,
                before_json,
                after_json,
                metadata_json
            )
            SELECT
                event_id,
                occurred_at,
                project_id,
                actor_type,
                actor_id,
                action,
                resource_type,
                resource_id,
                reason,
                before_json,
                after_json,
                metadata_json
            FROM legacy_administrative_audit_events
            """
        )
        connection.execute(
            "DROP TABLE legacy_administrative_audit_events"
        )

    @staticmethod
    def _migrate_webhook_events_table(
        connection: sqlite3.Connection,
    ) -> None:
        row = connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
            AND name = 'webhook_events'
            """
        ).fetchone()

        if (
            row is None
            or "execution_grant.issued" in row[0]
        ):
            return

        trigger_names = (
            "prevent_webhook_event_update",
            "prevent_webhook_event_delete",
            "enforce_webhook_delivery_project",
            "protect_webhook_delivery_identity",
            "prevent_webhook_deliveries_delete",
            "prevent_webhook_attempt_update",
            "prevent_webhook_attempt_delete",
        )
        index_names = (
            "idx_webhook_events_project",
            "idx_webhook_deliveries_due",
            "idx_webhook_deliveries_project",
            "idx_webhook_delivery_attempts_delivery",
        )

        for trigger_name in trigger_names:
            connection.execute(
                f"DROP TRIGGER IF EXISTS {trigger_name}"
            )

        for index_name in index_names:
            connection.execute(
                f"DROP INDEX IF EXISTS {index_name}"
            )

        connection.execute(
            """
            ALTER TABLE webhook_delivery_attempts
            RENAME TO legacy_webhook_delivery_attempts
            """
        )
        connection.execute(
            """
            ALTER TABLE webhook_deliveries
            RENAME TO legacy_webhook_deliveries
            """
        )
        connection.execute(
            """
            ALTER TABLE webhook_events
            RENAME TO legacy_webhook_events
            """
        )

        connection.execute(CREATE_WEBHOOK_EVENTS_TABLE)
        connection.execute(CREATE_WEBHOOK_DELIVERIES_TABLE)
        connection.execute(CREATE_WEBHOOK_DELIVERY_ATTEMPTS_TABLE)
        connection.execute(
            """
            INSERT INTO webhook_events
            SELECT * FROM legacy_webhook_events
            """
        )
        connection.execute(
            """
            INSERT INTO webhook_deliveries
            SELECT * FROM legacy_webhook_deliveries
            """
        )
        connection.execute(
            """
            INSERT INTO webhook_delivery_attempts
            SELECT * FROM legacy_webhook_delivery_attempts
            """
        )
        connection.execute(
            "DROP TABLE legacy_webhook_delivery_attempts"
        )
        connection.execute(
            "DROP TABLE legacy_webhook_deliveries"
        )
        connection.execute(
            "DROP TABLE legacy_webhook_events"
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
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute(CREATE_PROJECTS_TABLE)
            self._migrate_projects_table(connection)
            connection.execute(CREATE_PROJECT_API_KEYS_TABLE)
            self._migrate_project_api_keys_table(connection)
            connection.execute(
                CREATE_WEBHOOK_SUBSCRIPTIONS_TABLE
            )
            connection.execute(
                CREATE_WEBHOOK_SUBSCRIPTIONS_INDEX
            )
            connection.execute(
                CREATE_WEBHOOK_SUBSCRIPTIONS_IDENTITY_TRIGGER
            )
            connection.execute(
                CREATE_WEBHOOK_SUBSCRIPTIONS_DELETE_TRIGGER
            )
            connection.execute(CREATE_WEBHOOK_EVENTS_TABLE)
            self._migrate_webhook_events_table(connection)
            connection.execute(CREATE_WEBHOOK_EVENTS_INDEX)
            connection.execute(
                CREATE_WEBHOOK_EVENTS_UPDATE_TRIGGER
            )
            connection.execute(
                CREATE_WEBHOOK_EVENTS_DELETE_TRIGGER
            )
            connection.execute(CREATE_WEBHOOK_DELIVERIES_TABLE)
            connection.execute(
                CREATE_WEBHOOK_DELIVERIES_DUE_INDEX
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERIES_PROJECT_INDEX
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERY_PROJECT_TRIGGER
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERY_IDENTITY_TRIGGER
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERIES_DELETE_TRIGGER
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERY_ATTEMPTS_TABLE
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERY_ATTEMPTS_INDEX
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERY_ATTEMPTS_UPDATE_TRIGGER
            )
            connection.execute(
                CREATE_WEBHOOK_DELIVERY_ATTEMPTS_DELETE_TRIGGER
            )
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
            connection.execute(
                CREATE_ADMINISTRATIVE_AUDIT_EVENTS_TABLE
            )
            self._migrate_administrative_audit_events_table(
                connection
            )
            connection.execute(
                CREATE_ADMINISTRATIVE_AUDIT_EVENTS_INDEX
            )
            connection.execute(
                CREATE_ADMINISTRATIVE_AUDIT_PROJECT_INDEX
            )
            connection.execute(
                CREATE_ADMINISTRATIVE_AUDIT_UPDATE_TRIGGER
            )
            connection.execute(
                CREATE_ADMINISTRATIVE_AUDIT_DELETE_TRIGGER
            )
            connection.execute(CREATE_DECISIONS_TABLE)
            self._migrate_decisions_table(connection)
            connection.execute(
                CREATE_DECISIONS_PROJECT_TIME_INDEX
            )
            connection.execute(
                CREATE_DECISIONS_PROJECT_DECISION_INDEX
            )
            connection.execute(
                CREATE_DECISIONS_PROJECT_AGENT_INDEX
            )
            connection.execute(
                CREATE_DECISIONS_PROJECT_ACTION_INDEX
            )
            connection.execute(
                CREATE_DECISIONS_PROJECT_POLICY_INDEX
            )
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
            self._migrate_approval_requests_table(connection)
            connection.execute(
                CREATE_APPROVAL_REQUESTS_STATUS_INDEX
            )
            connection.execute(
                CREATE_APPROVAL_REQUESTS_EXPIRY_INDEX
            )
            connection.execute(CREATE_APPROVAL_LIFECYCLE_TRIGGER)
            connection.execute(CREATE_APPROVAL_DELETE_TRIGGER)
            connection.execute(CREATE_EXECUTION_GRANTS_TABLE)
            connection.execute(
                CREATE_EXECUTION_GRANTS_PROJECT_STATUS_INDEX
            )
            connection.execute(
                CREATE_EXECUTION_GRANT_SCOPE_TRIGGER
            )
            connection.execute(CREATE_APPROVAL_GRANT_TRIGGER)
            connection.execute(
                CREATE_EXECUTION_GRANT_UPDATE_TRIGGER
            )
            connection.execute(
                CREATE_EXECUTION_GRANT_DELETE_TRIGGER
            )
            connection.execute(CREATE_IDEMPOTENCY_RECORDS_TABLE)

            self._migrate_idempotency_records_table(
                connection
            )

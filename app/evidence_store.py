import json
import sqlite3
from datetime import datetime
from pathlib import Path
from uuid import UUID
from app.idempotency import IdempotencyRecord

from app.approval_models import (
    ApprovalRecord,
    ApprovalResolutionStatus,
    ApprovalStatus,
)
from app.authorization_models import AuthorizationResponse
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    PolicyVersionConflictError,
)
from app.policy_models import (
    Policy,
    ProjectPolicyConfiguration,
)
from app.project_models import (
    DEFAULT_PROJECT_ID,
    Project,
)

from app.api_keys import (
    ProjectApiKeyMetadata,
    ProjectApiKeyRecord,
)

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
    created_at TEXT NOT NULL
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

class EvidenceStore:
    def __init__(
        self,
        database_path: Path,
    ) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

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

    def initialize(self) -> None:
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self._connect() as connection:
            connection.execute(CREATE_PROJECTS_TABLE)
            connection.execute(CREATE_PROJECT_API_KEYS_TABLE)
            connection.execute(CREATE_PROJECT_POLICIES_TABLE)
            connection.execute(CREATE_PROJECT_POLICIES_INDEX)
            connection.execute(CREATE_DECISIONS_TABLE)
            self._migrate_decisions_table(connection)
            connection.execute(CREATE_APPROVAL_REQUESTS_TABLE)
            connection.execute(CREATE_IDEMPOTENCY_RECORDS_TABLE)

            self._migrate_idempotency_records_table(
                connection
            )

    @staticmethod
    def _insert_project(
        connection: sqlite3.Connection,
        project: Project,
    ) -> None:
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
                str(project.project_id),
                project.name,
                project.status,
                project.created_at.isoformat(),
            ),
        )

    def save_project(
        self,
        project: Project,
    ) -> None:
        with self._connect() as connection:
            self._insert_project(
                connection,
                project,
            )

    def get_project(
        self,
        project_id: UUID,
    ) -> Project | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    project_id,
                    name,
                    status,
                    created_at
                FROM projects
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        if row is None:
            return None

        return Project.model_validate(
            {
                "project_id": row["project_id"],
                "name": row["name"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
        )

    def _insert_authorization(
        self,
        connection: sqlite3.Connection,
        authorization: AuthorizationResponse,
    ) -> None:
        evidence_json = None

        if authorization.evidence is not None:
            evidence_json = json.dumps(
                authorization.evidence.model_dump(mode="json"),
                sort_keys=True,
            )

        context_json = json.dumps(
            authorization.context,
            sort_keys=True,
        )

        trace_json = json.dumps(
            [
                entry.model_dump(mode="json")
                for entry in authorization.trace
            ],
            sort_keys=True,
        )

        connection.execute(
            """
            INSERT INTO authorization_decisions (
                decision_id,
                project_id,
                evaluated_at,
                decision,
                policy_id,
                policy_version,
                reason,
                evidence_json,
                trace_json,
                agent,
                action,
                context_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(authorization.decision_id),
                str(authorization.project_id),
                authorization.evaluated_at.isoformat(),
                authorization.decision,
                authorization.policy,
                authorization.policy_version,
                authorization.reason,
                evidence_json,
                trace_json,
                authorization.agent,
                authorization.action,
                context_json,
            ),
        )


    def save(
        self,
        authorization: AuthorizationResponse,
    ) -> None:
        with self._connect() as connection:
            self._insert_authorization(
                connection,
                authorization,
            )

    @staticmethod
    def _row_to_authorization(
        row: sqlite3.Row,
    ) -> AuthorizationResponse:
        evidence = None

        if row["evidence_json"] is not None:
            evidence = json.loads(row["evidence_json"])

        if evidence is not None and "conditions" not in evidence:
            evidence = {
                "match": "all",
                "conditions": [
                    {
                        **evidence,
                        "matched": True,
                    }
                ],
            }

        return AuthorizationResponse.model_validate(
            {
                "decision_id": row["decision_id"],
                "project_id": row["project_id"],
                "evaluated_at": row["evaluated_at"],
                "decision": row["decision"],
                "policy": row["policy_id"],
                "policy_version": row["policy_version"],
                "reason": row["reason"],
                "evidence": evidence,
                "trace": json.loads(row["trace_json"]),
                "agent": row["agent"],
                "action": row["action"],
                "context": json.loads(row["context_json"]),
            }
        )

    def get(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> AuthorizationResponse | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT *
                FROM authorization_decisions
                WHERE decision_id = ?
                AND project_id = ?
                """,
                (
                    str(decision_id),
                    str(project_id),
                ),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_authorization(row)

    def get_idempotency_record(
        self,
        project_id: UUID,
        idempotency_key: str,
    ) -> IdempotencyRecord | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    project_id,
                    idempotency_key,
                    request_fingerprint,
                    decision_id,
                    created_at
                FROM idempotency_records
                WHERE project_id = ?
                AND idempotency_key = ?
                """,
                (
                    str(project_id),
                    idempotency_key,
                ),
            ).fetchone()

        if row is None:
            return None

        return IdempotencyRecord.model_validate(
            {
                "project_id": row["project_id"],
                "idempotency_key": row["idempotency_key"],
                "request_fingerprint": (
                    row["request_fingerprint"]
                ),
                "decision_id": row["decision_id"],
                "created_at": row["created_at"],
            }
        )
    

    def list_decisions(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[AuthorizationResponse]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT *
                FROM authorization_decisions
                WHERE project_id = ?
                ORDER BY evaluated_at DESC, decision_id DESC
                LIMIT ? OFFSET ?
                """,
                (
                    str(project_id),
                    limit,
                    offset,
                ),
            ).fetchall()

        return [
            self._row_to_authorization(row)
            for row in rows
        ]

    def count(
        self,
        project_id: UUID,
    ) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM authorization_decisions
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        return int(row[0])

    @staticmethod
    def _row_to_approval(
        row: sqlite3.Row,
    ) -> ApprovalRecord:
        return ApprovalRecord.model_validate(
            {
                "decision_id": row["decision_id"],
                "status": row["status"],
                "requested_at": row["requested_at"],
                "resolved_at": row["resolved_at"],
                "resolved_by": row["resolved_by"],
            }
        )


    def _insert_approval(
        self,
        connection: sqlite3.Connection,
        approval: ApprovalRecord,
    ) -> None:
        connection.execute(
            """
            INSERT INTO approval_requests (
                decision_id,
                status,
                requested_at,
                resolved_at,
                resolved_by
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(approval.decision_id),
                approval.status,
                approval.requested_at.isoformat(),
                (
                    approval.resolved_at.isoformat()
                    if approval.resolved_at is not None
                    else None
                ),
                approval.resolved_by,
            ),
        )


    def save_approval(
        self,
        approval: ApprovalRecord,
    ) -> None:
        with self._connect() as connection:
            self._insert_approval(
                connection,
                approval,
            )


    def get_approval(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> ApprovalRecord | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT approval_requests.*
                FROM approval_requests
                JOIN authorization_decisions
                    ON authorization_decisions.decision_id
                    = approval_requests.decision_id
                WHERE approval_requests.decision_id = ?
                AND authorization_decisions.project_id = ?
                """,
                (
                    str(decision_id),
                    str(project_id),
                ),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_approval(row)

    def save_authorization_with_approval(
        self,
        authorization: AuthorizationResponse,
        approval: ApprovalRecord | None,
        idempotency_record: IdempotencyRecord | None = None,
    ) -> None:
        with self._connect() as connection:
            self._insert_authorization(
                connection,
                authorization,
            )

            if approval is not None:
                if (
                    approval.decision_id
                    != authorization.decision_id
                ):
                    raise ValueError(
                        "Approval decision_id must match "
                        "authorization decision_id."
                    )

                self._insert_approval(
                    connection,
                    approval,
                )

            if idempotency_record is not None:
                if (
                    idempotency_record.project_id
                    != authorization.project_id
                ):
                    raise ValueError(
                        "Idempotency record project_id must match "
                        "authorization project_id."
                    )

                if (
                    idempotency_record.decision_id
                    != authorization.decision_id
                ):
                    raise ValueError(
                        "Idempotency record decision_id must match "
                        "authorization decision_id."
                    )

                self._insert_idempotency_record(
                    connection,
                    idempotency_record,
                )

    def resolve_approval(
        self,
        decision_id: UUID,
        project_id: UUID,
        status: ApprovalResolutionStatus,
        resolved_by: str,
        resolved_at: datetime,
    ) -> ApprovalRecord:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            result = connection.execute(
                """
                UPDATE approval_requests
                SET
                    status = ?,
                    resolved_at = ?,
                    resolved_by = ?
                WHERE decision_id = ?
                AND status = 'PENDING'
                AND EXISTS (
                    SELECT 1
                    FROM authorization_decisions
                    WHERE authorization_decisions.decision_id
                        = approval_requests.decision_id
                    AND authorization_decisions.project_id = ?
                )
                """,
                (
                    status,
                    resolved_at.isoformat(),
                    resolved_by,
                    str(decision_id),
                    str(project_id),
                ),
            )

            if result.rowcount == 0:
                row = connection.execute(
                    """
                    SELECT approval_requests.*
                    FROM approval_requests
                    JOIN authorization_decisions
                        ON authorization_decisions.decision_id
                        = approval_requests.decision_id
                    WHERE approval_requests.decision_id = ?
                    AND authorization_decisions.project_id = ?
                    """,
                    (
                        str(decision_id),
                        str(project_id),
                    ),
                ).fetchone()

                if row is None:
                    raise ApprovalNotFoundError(decision_id)

                current_approval = self._row_to_approval(row)

                raise ApprovalAlreadyResolvedError(
                    decision_id=decision_id,
                    current_status=current_approval.status,
                )

            row = connection.execute(
                """
                SELECT approval_requests.*
                FROM approval_requests
                JOIN authorization_decisions
                    ON authorization_decisions.decision_id
                    = approval_requests.decision_id
                WHERE approval_requests.decision_id = ?
                AND authorization_decisions.project_id = ?
                """,
                (
                    str(decision_id),
                    str(project_id),
                ),
            ).fetchone()

        return self._row_to_approval(row)

    def list_approvals(
        self,
        project_id: UUID,
        status: ApprovalStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ApprovalRecord]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            if status is None:
                rows = connection.execute(
                    """
                    SELECT approval_requests.*
                    FROM approval_requests
                    JOIN authorization_decisions
                        ON authorization_decisions.decision_id
                        = approval_requests.decision_id
                    WHERE authorization_decisions.project_id = ?
                    ORDER BY
                        approval_requests.requested_at DESC,
                        approval_requests.decision_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (
                        str(project_id),
                        limit,
                        offset,
                    ),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT approval_requests.*
                    FROM approval_requests
                    JOIN authorization_decisions
                        ON authorization_decisions.decision_id
                        = approval_requests.decision_id
                    WHERE authorization_decisions.project_id = ?
                    AND approval_requests.status = ?
                    ORDER BY
                        approval_requests.requested_at DESC,
                        approval_requests.decision_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (
                        str(project_id),
                        status,
                        limit,
                        offset,
                    ),
                ).fetchall()

        return [
            self._row_to_approval(row)
            for row in rows
        ]


    def count_approvals(
        self,
        project_id: UUID,
        status: ApprovalStatus | None = None,
    ) -> int:
        with self._connect() as connection:
            if status is None:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM approval_requests
                    JOIN authorization_decisions
                        ON authorization_decisions.decision_id
                        = approval_requests.decision_id
                    WHERE authorization_decisions.project_id = ?
                    """,
                    (str(project_id),),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM approval_requests
                    JOIN authorization_decisions
                        ON authorization_decisions.decision_id
                        = approval_requests.decision_id
                    WHERE authorization_decisions.project_id = ?
                    AND approval_requests.status = ?
                    """,
                    (
                        str(project_id),
                        status,
                    ),
                ).fetchone()

        return int(row[0])

    @staticmethod
    def _insert_idempotency_record(
        connection: sqlite3.Connection,
        record: IdempotencyRecord,
    ) -> None:
        connection.execute(
            """
            INSERT INTO idempotency_records (
                project_id,
                idempotency_key,
                request_fingerprint,
                decision_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(record.project_id),
                record.idempotency_key,
                record.request_fingerprint,
                str(record.decision_id),
                record.created_at.isoformat(),
            ),
        )

    def save_project_with_api_key(
        self,
        project: Project,
        api_key: ProjectApiKeyRecord,
        policies: list[Policy] | None = None,
    ) -> None:
        if api_key.project_id != project.project_id:
            raise ValueError(
                "API key project_id must match "
                "project project_id."
            )

        with self._connect() as connection:
            self._insert_project(
                connection,
                project,
            )

            self._insert_project_api_key(
                connection,
                api_key,
            )

            for policy in policies or []:
                self._insert_seed_project_policy(
                    connection=connection,
                    project_id=project.project_id,
                    policy=policy,
                    updated_at=project.created_at,
                )


    def save_project_api_key(
        self,
        api_key: ProjectApiKeyRecord,
    ) -> None:
        with self._connect() as connection:
            self._insert_project_api_key(
                connection,
                api_key,
            )

    @staticmethod
    def _insert_project_api_key(
        connection: sqlite3.Connection,
        api_key: ProjectApiKeyRecord,
    ) -> None:
        connection.execute(
            """
            INSERT INTO project_api_keys (
                api_key_id,
                project_id,
                key_prefix,
                key_hash,
                created_at,
                revoked_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(api_key.api_key_id),
                str(api_key.project_id),
                api_key.key_prefix,
                api_key.key_hash,
                api_key.created_at.isoformat(),
                (
                    api_key.revoked_at.isoformat()
                    if api_key.revoked_at is not None
                    else None
                ),
            ),
        )

    @staticmethod
    def _row_to_project_api_key_metadata(
        row: sqlite3.Row,
    ) -> ProjectApiKeyMetadata:
        return ProjectApiKeyMetadata.model_validate(
            {
                "api_key_id": row["api_key_id"],
                "project_id": row["project_id"],
                "key_prefix": row["key_prefix"],
                "created_at": row["created_at"],
                "revoked_at": row["revoked_at"],
            }
        )

    @staticmethod
    def _row_to_project_policy_configuration(
        row: sqlite3.Row,
    ) -> ProjectPolicyConfiguration:
        return ProjectPolicyConfiguration.model_validate(
            {
                "project_id": row["project_id"],
                "policy": json.loads(row["policy_json"]),
                "enabled": bool(row["enabled"]),
                "updated_at": row["updated_at"],
            }
        )

    @staticmethod
    def _insert_seed_project_policy(
        connection: sqlite3.Connection,
        project_id: UUID,
        policy: Policy,
        updated_at: datetime,
    ) -> None:
        connection.execute(
            """
            INSERT OR IGNORE INTO project_policies (
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
                str(project_id),
                policy.id,
                policy.version,
                json.dumps(
                    policy.model_dump(mode="json"),
                    sort_keys=True,
                ),
                updated_at.isoformat(),
            ),
        )

    def seed_project_policies(
        self,
        project_id: UUID,
        policies: list[Policy],
        seeded_at: datetime,
    ) -> None:
        with self._connect() as connection:
            for policy in policies:
                self._insert_seed_project_policy(
                    connection=connection,
                    project_id=project_id,
                    policy=policy,
                    updated_at=seeded_at,
                )

    def list_project_policy_configurations(
        self,
        project_id: UUID,
    ) -> list[ProjectPolicyConfiguration]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    project_id,
                    policy_id,
                    version,
                    policy_json,
                    enabled,
                    updated_at
                FROM project_policies
                WHERE project_id = ?
                ORDER BY policy_id
                """,
                (str(project_id),),
            ).fetchall()

        return [
            self._row_to_project_policy_configuration(row)
            for row in rows
        ]

    def list_project_policies(
        self,
        project_id: UUID,
    ) -> list[Policy]:
        return [
            configuration.policy
            for configuration in (
                self.list_project_policy_configurations(
                    project_id
                )
            )
            if configuration.enabled
        ]

    def get_project_policy_configuration(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> ProjectPolicyConfiguration | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    project_id,
                    policy_id,
                    version,
                    policy_json,
                    enabled,
                    updated_at
                FROM project_policies
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    str(project_id),
                    policy_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_project_policy_configuration(row)

    def get_project_policy(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> Policy | None:
        configuration = (
            self.get_project_policy_configuration(
                project_id=project_id,
                policy_id=policy_id,
            )
        )

        if (
            configuration is None
            or not configuration.enabled
        ):
            return None

        return configuration.policy

    def save_project_policy(
        self,
        project_id: UUID,
        policy: Policy,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            current_row = connection.execute(
                """
                SELECT version
                FROM project_policies
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    str(project_id),
                    policy.id,
                ),
            ).fetchone()

            expected_version = (
                1
                if current_row is None
                else int(current_row["version"]) + 1
            )

            if policy.version != expected_version:
                raise PolicyVersionConflictError(
                    policy_id=policy.id,
                    expected_version=expected_version,
                    provided_version=policy.version,
                )

            policy_json = json.dumps(
                policy.model_dump(mode="json"),
                sort_keys=True,
            )

            if current_row is None:
                try:
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
                            str(project_id),
                            policy.id,
                            policy.version,
                            policy_json,
                            updated_at.isoformat(),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    concurrent_row = connection.execute(
                        """
                        SELECT version
                        FROM project_policies
                        WHERE project_id = ?
                        AND policy_id = ?
                        """,
                        (
                            str(project_id),
                            policy.id,
                        ),
                    ).fetchone()

                    if concurrent_row is None:
                        raise

                    raise PolicyVersionConflictError(
                        policy_id=policy.id,
                        expected_version=(
                            int(concurrent_row["version"]) + 1
                        ),
                        provided_version=policy.version,
                    ) from exc
            else:
                current_version = int(current_row["version"])

                update_result = connection.execute(
                    """
                    UPDATE project_policies
                    SET
                        version = ?,
                        policy_json = ?,
                        enabled = 1,
                        updated_at = ?
                    WHERE project_id = ?
                    AND policy_id = ?
                    AND version = ?
                    """,
                    (
                        policy.version,
                        policy_json,
                        updated_at.isoformat(),
                        str(project_id),
                        policy.id,
                        current_version,
                    ),
                )

                if update_result.rowcount != 1:
                    concurrent_row = connection.execute(
                        """
                        SELECT version
                        FROM project_policies
                        WHERE project_id = ?
                        AND policy_id = ?
                        """,
                        (
                            str(project_id),
                            policy.id,
                        ),
                    ).fetchone()

                    concurrent_expected_version = (
                        1
                        if concurrent_row is None
                        else int(concurrent_row["version"]) + 1
                    )

                    raise PolicyVersionConflictError(
                        policy_id=policy.id,
                        expected_version=(
                            concurrent_expected_version
                        ),
                        provided_version=policy.version,
                    )

            row = connection.execute(
                """
                SELECT
                    project_id,
                    policy_id,
                    version,
                    policy_json,
                    enabled,
                    updated_at
                FROM project_policies
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    str(project_id),
                    policy.id,
                ),
            ).fetchone()

        return self._row_to_project_policy_configuration(row)

    def disable_project_policy(
        self,
        project_id: UUID,
        policy_id: str,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            existing = connection.execute(
                """
                SELECT 1
                FROM project_policies
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    str(project_id),
                    policy_id,
                ),
            ).fetchone()

            if existing is None:
                return None

            connection.execute(
                """
                UPDATE project_policies
                SET
                    updated_at = CASE
                        WHEN enabled = 1 THEN ?
                        ELSE updated_at
                    END,
                    enabled = 0
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    updated_at.isoformat(),
                    str(project_id),
                    policy_id,
                ),
            )

            row = connection.execute(
                """
                SELECT
                    project_id,
                    policy_id,
                    version,
                    policy_json,
                    enabled,
                    updated_at
                FROM project_policies
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    str(project_id),
                    policy_id,
                ),
            ).fetchone()

        return self._row_to_project_policy_configuration(row)

    def list_project_api_keys(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ProjectApiKeyMetadata]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    api_key_id,
                    project_id,
                    key_prefix,
                    created_at,
                    revoked_at
                FROM project_api_keys
                WHERE project_id = ?
                ORDER BY created_at DESC, api_key_id DESC
                LIMIT ? OFFSET ?
                """,
                (
                    str(project_id),
                    limit,
                    offset,
                ),
            ).fetchall()

        return [
            self._row_to_project_api_key_metadata(row)
            for row in rows
        ]

    def count_project_api_keys(
        self,
        project_id: UUID,
    ) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM project_api_keys
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        return int(row[0])

    def revoke_project_api_key(
        self,
        project_id: UUID,
        api_key_id: UUID,
        revoked_at: datetime,
    ) -> ProjectApiKeyMetadata | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            connection.execute(
                """
                UPDATE project_api_keys
                SET revoked_at = COALESCE(revoked_at, ?)
                WHERE project_id = ?
                AND api_key_id = ?
                """,
                (
                    revoked_at.isoformat(),
                    str(project_id),
                    str(api_key_id),
                ),
            )

            row = connection.execute(
                """
                SELECT
                    api_key_id,
                    project_id,
                    key_prefix,
                    created_at,
                    revoked_at
                FROM project_api_keys
                WHERE project_id = ?
                AND api_key_id = ?
                """,
                (
                    str(project_id),
                    str(api_key_id),
                ),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_project_api_key_metadata(row)

    def get_active_project_by_api_key_hash(
        self,
        key_hash: str,
    ) -> Project | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    projects.project_id,
                    projects.name,
                    projects.status,
                    projects.created_at
                FROM projects
                INNER JOIN project_api_keys
                    ON project_api_keys.project_id
                    = projects.project_id
                WHERE project_api_keys.key_hash = ?
                AND project_api_keys.revoked_at IS NULL
                AND projects.status = 'ACTIVE'
                """,
                (key_hash,),
            ).fetchone()

        if row is None:
            return None

        return Project.model_validate(
            {
                "project_id": row["project_id"],
                "name": row["name"],
                "status": row["status"],
                "created_at": row["created_at"],
            }
        )

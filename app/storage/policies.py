import json
import sqlite3
from datetime import datetime
from uuid import UUID

from app.exceptions import (
    PolicyVersionAlreadyCurrentError,
    PolicyVersionConflictError,
    PolicyVersionNotFoundError,
)
from app.policy_models import (
    Policy,
    PolicyVersionChangeType,
    ProjectPolicyConfiguration,
    ProjectPolicyVersion,
)
from app.storage.database import SQLiteDatabase


class ProjectPolicyRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_configuration(
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
    def _row_to_version(
        row: sqlite3.Row,
    ) -> ProjectPolicyVersion:
        return ProjectPolicyVersion.model_validate(
            {
                "project_id": row["project_id"],
                "policy_id": row["policy_id"],
                "version": row["version"],
                "policy": json.loads(row["policy_json"]),
                "change_type": row["change_type"],
                "source_version": row["source_version"],
                "created_at": row["created_at"],
            }
        )

    @staticmethod
    def insert_version(
        connection: sqlite3.Connection,
        project_id: UUID,
        policy: Policy,
        change_type: PolicyVersionChangeType,
        created_at: datetime,
        source_version: int | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO project_policy_versions (
                project_id,
                policy_id,
                version,
                policy_json,
                change_type,
                source_version,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(project_id),
                policy.id,
                policy.version,
                json.dumps(
                    policy.model_dump(mode="json"),
                    sort_keys=True,
                ),
                change_type,
                source_version,
                created_at.isoformat(),
            ),
        )

    @staticmethod
    def insert_seed(
        connection: sqlite3.Connection,
        project_id: UUID,
        policy: Policy,
        updated_at: datetime,
    ) -> None:
        insert_result = connection.execute(
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

        if insert_result.rowcount == 1:
            ProjectPolicyRepository.insert_version(
                connection=connection,
                project_id=project_id,
                policy=policy,
                change_type="CREATED",
                created_at=updated_at,
            )

    def seed(
        self,
        project_id: UUID,
        policies: list[Policy],
        seeded_at: datetime,
    ) -> None:
        with self.database.connect() as connection:
            for policy in policies:
                self.insert_seed(
                    connection=connection,
                    project_id=project_id,
                    policy=policy,
                    updated_at=seeded_at,
                )

    def list_configurations(
        self,
        project_id: UUID,
    ) -> list[ProjectPolicyConfiguration]:
        with self.database.connect() as connection:
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
            self._row_to_configuration(row)
            for row in rows
        ]

    def list_active(self, project_id: UUID) -> list[Policy]:
        return [
            configuration.policy
            for configuration in self.list_configurations(
                project_id
            )
            if configuration.enabled
        ]

    def get_configuration(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> ProjectPolicyConfiguration | None:
        with self.database.connect() as connection:
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

        return self._row_to_configuration(row)

    def get_active(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> Policy | None:
        configuration = self.get_configuration(
            project_id=project_id,
            policy_id=policy_id,
        )

        if (
            configuration is None
            or not configuration.enabled
        ):
            return None

        return configuration.policy

    def _save_with_connection(
        self,
        connection: sqlite3.Connection,
        project_id: UUID,
        policy: Policy,
        updated_at: datetime,
        change_type: PolicyVersionChangeType = "UPDATED",
        source_version: int | None = None,
    ) -> ProjectPolicyConfiguration:
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
            effective_change_type: PolicyVersionChangeType = (
                "CREATED"
            )

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
            effective_change_type = change_type
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

        self.insert_version(
            connection=connection,
            project_id=project_id,
            policy=policy,
            change_type=effective_change_type,
            created_at=updated_at,
            source_version=(
                source_version
                if effective_change_type == "ROLLBACK"
                else None
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
                policy.id,
            ),
        ).fetchone()

        return self._row_to_configuration(row)

    def save(
        self,
        project_id: UUID,
        policy: Policy,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration:
        with self.database.connect() as connection:
            return self._save_with_connection(
                connection=connection,
                project_id=project_id,
                policy=policy,
                updated_at=updated_at,
            )

    def list_versions(
        self,
        project_id: UUID,
        policy_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ProjectPolicyVersion]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    project_id,
                    policy_id,
                    version,
                    policy_json,
                    change_type,
                    source_version,
                    created_at
                FROM project_policy_versions
                WHERE project_id = ?
                AND policy_id = ?
                ORDER BY version DESC
                LIMIT ? OFFSET ?
                """,
                (
                    str(project_id),
                    policy_id,
                    limit,
                    offset,
                ),
            ).fetchall()

        return [
            self._row_to_version(row)
            for row in rows
        ]

    def count_versions(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM project_policy_versions
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    str(project_id),
                    policy_id,
                ),
            ).fetchone()

        return int(row[0])

    def get_version(
        self,
        project_id: UUID,
        policy_id: str,
        version: int,
    ) -> ProjectPolicyVersion | None:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    project_id,
                    policy_id,
                    version,
                    policy_json,
                    change_type,
                    source_version,
                    created_at
                FROM project_policy_versions
                WHERE project_id = ?
                AND policy_id = ?
                AND version = ?
                """,
                (
                    str(project_id),
                    policy_id,
                    version,
                ),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_version(row)

    def rollback(
        self,
        project_id: UUID,
        policy_id: str,
        source_version: int,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            historical_row = connection.execute(
                """
                SELECT
                    project_id,
                    policy_id,
                    version,
                    policy_json,
                    change_type,
                    source_version,
                    created_at
                FROM project_policy_versions
                WHERE project_id = ?
                AND policy_id = ?
                AND version = ?
                """,
                (
                    str(project_id),
                    policy_id,
                    source_version,
                ),
            ).fetchone()

            if historical_row is None:
                raise PolicyVersionNotFoundError(
                    policy_id=policy_id,
                    version=source_version,
                )

            current_row = connection.execute(
                """
                SELECT version
                FROM project_policies
                WHERE project_id = ?
                AND policy_id = ?
                """,
                (
                    str(project_id),
                    policy_id,
                ),
            ).fetchone()

            if current_row is None:
                raise PolicyVersionNotFoundError(
                    policy_id=policy_id,
                    version=source_version,
                )

            current_version = int(current_row["version"])

            if source_version == current_version:
                raise PolicyVersionAlreadyCurrentError(
                    policy_id=policy_id,
                    version=source_version,
                )

            historical_version = self._row_to_version(
                historical_row
            )
            restored_policy = (
                historical_version.policy.model_copy(
                    update={
                        "version": current_version + 1,
                    }
                )
            )

            return self._save_with_connection(
                connection=connection,
                project_id=project_id,
                policy=restored_policy,
                updated_at=updated_at,
                change_type="ROLLBACK",
                source_version=source_version,
            )

    def disable(
        self,
        project_id: UUID,
        policy_id: str,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration | None:
        with self.database.connect() as connection:
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

        return self._row_to_configuration(row)

import json
import sqlite3
from datetime import datetime
from uuid import UUID

from app.exceptions import PolicyVersionConflictError
from app.policy_models import (
    Policy,
    ProjectPolicyConfiguration,
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
    def insert_seed(
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

    def save(
        self,
        project_id: UUID,
        policy: Policy,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration:
        with self.database.connect() as connection:
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

        return self._row_to_configuration(row)

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

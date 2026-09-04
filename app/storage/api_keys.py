import sqlite3
from datetime import datetime
from uuid import UUID

from app.api_keys import (
    ProjectApiKeyMetadata,
    ProjectApiKeyPrincipal,
    ProjectApiKeyRecord,
    get_api_key_prefix,
    verify_api_key,
)
from app.project_models import Project
from app.storage.database import SQLiteDatabase


class ProjectApiKeyRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def insert(
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
                role,
                created_at,
                revoked_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(api_key.api_key_id),
                str(api_key.project_id),
                api_key.key_prefix,
                api_key.key_hash,
                api_key.role,
                api_key.created_at.isoformat(),
                (
                    api_key.revoked_at.isoformat()
                    if api_key.revoked_at is not None
                    else None
                ),
            ),
        )

    @staticmethod
    def _row_to_metadata(
        row: sqlite3.Row,
    ) -> ProjectApiKeyMetadata:
        return ProjectApiKeyMetadata.model_validate(
            {
                "api_key_id": row["api_key_id"],
                "project_id": row["project_id"],
                "key_prefix": row["key_prefix"],
                "role": row["role"],
                "created_at": row["created_at"],
                "revoked_at": row["revoked_at"],
            }
        )

    def save(self, api_key: ProjectApiKeyRecord) -> None:
        with self.database.connect() as connection:
            self.insert(connection, api_key)

    @classmethod
    def get_metadata_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        api_key_id: UUID,
    ) -> ProjectApiKeyMetadata | None:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT
                api_key_id,
                project_id,
                key_prefix,
                role,
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

        return cls._row_to_metadata(row)

    def list(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ProjectApiKeyMetadata]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT
                    api_key_id,
                    project_id,
                    key_prefix,
                    role,
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
            self._row_to_metadata(row)
            for row in rows
        ]

    def count(self, project_id: UUID) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM project_api_keys
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        return int(row[0])

    @classmethod
    def revoke_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        api_key_id: UUID,
        revoked_at: datetime,
    ) -> ProjectApiKeyMetadata | None:
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

        return cls.get_metadata_with_connection(
            connection=connection,
            project_id=project_id,
            api_key_id=api_key_id,
        )

    def revoke(
        self,
        project_id: UUID,
        api_key_id: UUID,
        revoked_at: datetime,
    ) -> ProjectApiKeyMetadata | None:
        with self.database.connect() as connection:
            return self.revoke_with_connection(
                connection=connection,
                project_id=project_id,
                api_key_id=api_key_id,
                revoked_at=revoked_at,
            )

    def get_active_principal_by_api_key(
        self,
        api_key: str,
    ) -> ProjectApiKeyPrincipal | None:
        try:
            key_prefix = get_api_key_prefix(api_key)
        except ValueError:
            return None
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    project_api_keys.api_key_id,
                    project_api_keys.role,
                    project_api_keys.key_hash,
                    projects.project_id,
                    projects.name,
                    projects.status,
                    projects.created_at,
                    projects.updated_at
                FROM projects
                INNER JOIN project_api_keys
                    ON project_api_keys.project_id
                    = projects.project_id
                WHERE project_api_keys.key_prefix = ?
                AND project_api_keys.revoked_at IS NULL
                AND projects.status = 'ACTIVE'
                """,
                (key_prefix,),
            ).fetchone()

        if row is None or not verify_api_key(api_key, row["key_hash"]):
            return None

        # Hashing happens outside the connection. Recheck revocation and project
        # status afterwards, so a revocation during the KDF is not ignored.
        with self.database.connect() as connection:
            active = connection.execute(
                """
                SELECT 1 FROM project_api_keys AS k
                JOIN projects AS p ON p.project_id = k.project_id
                WHERE k.api_key_id = ? AND k.key_hash = ?
                AND k.revoked_at IS NULL AND p.status = 'ACTIVE'
                """,
                (row["api_key_id"], row["key_hash"]),
            ).fetchone()
        if active is None:
            return None

        return ProjectApiKeyPrincipal(
            api_key_id=row["api_key_id"],
            role=row["role"],
            project=Project.model_validate(
                {
                    "project_id": row["project_id"],
                    "name": row["name"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
            ),
        )

    def get_active_project_by_api_key(
        self,
        api_key: str,
    ) -> Project | None:
        principal = self.get_active_principal_by_api_key(api_key)
        return principal.project if principal is not None else None

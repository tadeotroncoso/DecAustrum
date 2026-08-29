import sqlite3
from datetime import datetime
from uuid import UUID

from app.project_models import Project, ProjectStatus
from app.storage.database import SQLiteDatabase


class ProjectRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_project(row: sqlite3.Row) -> Project:
        return Project.model_validate(
            {
                "project_id": row["project_id"],
                "name": row["name"],
                "status": row["status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )

    @staticmethod
    def insert(
        connection: sqlite3.Connection,
        project: Project,
    ) -> None:
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

    def save(self, project: Project) -> None:
        with self.database.connect() as connection:
            self.insert(connection, project)

    def get(self, project_id: UUID) -> Project | None:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    project_id,
                    name,
                    status,
                    created_at,
                    updated_at
                FROM projects
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_project(row)

    def list(
        self,
        status: ProjectStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[Project]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            if status is None:
                rows = connection.execute(
                    """
                    SELECT
                        project_id,
                        name,
                        status,
                        created_at,
                        updated_at
                    FROM projects
                    ORDER BY created_at DESC, project_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (
                        limit,
                        offset,
                    ),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT
                        project_id,
                        name,
                        status,
                        created_at,
                        updated_at
                    FROM projects
                    WHERE status = ?
                    ORDER BY created_at DESC, project_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (
                        status,
                        limit,
                        offset,
                    ),
                ).fetchall()

        return [
            self._row_to_project(row)
            for row in rows
        ]

    def count(
        self,
        status: ProjectStatus | None = None,
    ) -> int:
        with self.database.connect() as connection:
            if status is None:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM projects
                    """
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM projects
                    WHERE status = ?
                    """,
                    (status,),
                ).fetchone()

        return int(row[0])

    def update_status(
        self,
        project_id: UUID,
        status: ProjectStatus,
        updated_at: datetime,
    ) -> Project | None:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            connection.execute(
                """
                UPDATE projects
                SET
                    updated_at = CASE
                        WHEN status != ? THEN ?
                        ELSE updated_at
                    END,
                    status = ?
                WHERE project_id = ?
                """,
                (
                    status,
                    updated_at.isoformat(),
                    status,
                    str(project_id),
                ),
            )

            row = connection.execute(
                """
                SELECT
                    project_id,
                    name,
                    status,
                    created_at,
                    updated_at
                FROM projects
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_project(row)

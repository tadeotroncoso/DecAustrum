import sqlite3
from uuid import UUID

from app.project_models import Project
from app.storage.database import SQLiteDatabase


class ProjectRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

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

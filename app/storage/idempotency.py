import sqlite3
from uuid import UUID

from app.idempotency import IdempotencyRecord
from app.storage.database import SQLiteDatabase


class IdempotencyRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def insert(
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

    def get(
        self,
        project_id: UUID,
        idempotency_key: str,
    ) -> IdempotencyRecord | None:
        with self.database.connect() as connection:
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

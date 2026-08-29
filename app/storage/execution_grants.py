import sqlite3
from datetime import datetime
from uuid import UUID

from app.execution_models import ExecutionGrantRecord
from app.storage.database import SQLiteDatabase


class ExecutionGrantRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_grant(
        row: sqlite3.Row,
    ) -> ExecutionGrantRecord:
        return ExecutionGrantRecord.model_validate(
            {
                "version": 1,
                "grant_id": row["grant_id"],
                "decision_id": row["decision_id"],
                "project_id": row["project_id"],
                "status": row["status"],
                "request_fingerprint": row[
                    "request_fingerprint"
                ],
                "token_hash": row["token_hash"],
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
                "consumed_at": row["consumed_at"],
                "consumed_by": row["consumed_by"],
            }
        )

    @staticmethod
    def insert(
        connection: sqlite3.Connection,
        grant: ExecutionGrantRecord,
    ) -> None:
        connection.execute(
            """
            INSERT INTO execution_grants (
                grant_id,
                decision_id,
                project_id,
                status,
                request_fingerprint,
                token_hash,
                issued_at,
                expires_at,
                consumed_at,
                consumed_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(grant.grant_id),
                str(grant.decision_id),
                str(grant.project_id),
                grant.status,
                grant.request_fingerprint,
                grant.token_hash,
                grant.issued_at.isoformat(),
                grant.expires_at.isoformat(),
                (
                    grant.consumed_at.isoformat()
                    if grant.consumed_at is not None
                    else None
                ),
                grant.consumed_by,
            ),
        )

    @classmethod
    def get_with_connection(
        cls,
        connection: sqlite3.Connection,
        grant_id: UUID,
        project_id: UUID,
    ) -> ExecutionGrantRecord | None:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM execution_grants
            WHERE grant_id = ?
            AND project_id = ?
            """,
            (str(grant_id), str(project_id)),
        ).fetchone()

        if row is None:
            return None

        return cls._row_to_grant(row)

    @classmethod
    def get_by_decision_with_connection(
        cls,
        connection: sqlite3.Connection,
        decision_id: UUID,
        project_id: UUID,
    ) -> ExecutionGrantRecord | None:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM execution_grants
            WHERE decision_id = ?
            AND project_id = ?
            """,
            (str(decision_id), str(project_id)),
        ).fetchone()

        if row is None:
            return None

        return cls._row_to_grant(row)

    def get(
        self,
        grant_id: UUID,
        project_id: UUID,
    ) -> ExecutionGrantRecord | None:
        with self.database.connect() as connection:
            return self.get_with_connection(
                connection=connection,
                grant_id=grant_id,
                project_id=project_id,
            )

    def get_by_decision(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> ExecutionGrantRecord | None:
        with self.database.connect() as connection:
            return self.get_by_decision_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
            )

    @classmethod
    def consume_with_connection(
        cls,
        connection: sqlite3.Connection,
        grant_id: UUID,
        project_id: UUID,
        token_hash: str,
        consumed_at: datetime,
        consumed_by: str,
    ) -> ExecutionGrantRecord | None:
        result = connection.execute(
            """
            UPDATE execution_grants
            SET
                status = 'CONSUMED',
                consumed_at = ?,
                consumed_by = ?
            WHERE grant_id = ?
            AND project_id = ?
            AND token_hash = ?
            AND status = 'ACTIVE'
            AND expires_at > ?
            """,
            (
                consumed_at.isoformat(),
                consumed_by,
                str(grant_id),
                str(project_id),
                token_hash,
                consumed_at.isoformat(),
            ),
        )

        if result.rowcount == 0:
            return None

        return cls.get_with_connection(
            connection=connection,
            grant_id=grant_id,
            project_id=project_id,
        )

    @classmethod
    def expire_with_connection(
        cls,
        connection: sqlite3.Connection,
        grant_id: UUID,
        project_id: UUID,
        expired_at: datetime,
    ) -> ExecutionGrantRecord | None:
        result = connection.execute(
            """
            UPDATE execution_grants
            SET status = 'EXPIRED'
            WHERE grant_id = ?
            AND project_id = ?
            AND status = 'ACTIVE'
            AND expires_at <= ?
            """,
            (
                str(grant_id),
                str(project_id),
                expired_at.isoformat(),
            ),
        )

        if result.rowcount == 0:
            return None

        return cls.get_with_connection(
            connection=connection,
            grant_id=grant_id,
            project_id=project_id,
        )

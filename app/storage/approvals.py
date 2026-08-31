import sqlite3
from datetime import datetime
from uuid import UUID

from app.approval_models import (
    ApprovalRecord,
    ApprovalResolutionStatus,
    ApprovalStatus,
)
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
)
from app.storage.database import SQLiteDatabase


class ApprovalRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_approval(
        row: sqlite3.Row,
    ) -> ApprovalRecord:
        return ApprovalRecord.model_validate(
            {
                "decision_id": row["decision_id"],
                "status": row["status"],
                "requested_at": row["requested_at"],
                "expires_at": row["expires_at"],
                "resolved_at": row["resolved_at"],
                "resolved_by": row["resolved_by"],
            }
        )

    @staticmethod
    def insert(
        connection: sqlite3.Connection,
        approval: ApprovalRecord,
    ) -> None:
        connection.execute(
            """
            INSERT INTO approval_requests (
                decision_id,
                status,
                requested_at,
                expires_at,
                resolved_at,
                resolved_by
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(approval.decision_id),
                approval.status,
                approval.requested_at.isoformat(),
                (
                    approval.expires_at.isoformat()
                    if approval.expires_at is not None
                    else None
                ),
                (
                    approval.resolved_at.isoformat()
                    if approval.resolved_at is not None
                    else None
                ),
                approval.resolved_by,
            ),
        )

    def save(self, approval: ApprovalRecord) -> None:
        with self.database.connect() as connection:
            self.insert(connection, approval)

    @classmethod
    def get_with_connection(
        cls,
        connection: sqlite3.Connection,
        decision_id: UUID,
        project_id: UUID,
    ) -> ApprovalRecord | None:
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

        return cls._row_to_approval(row)

    def get(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> ApprovalRecord | None:
        with self.database.connect() as connection:
            return self.get_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
            )

    @classmethod
    def resolve_with_connection(
        cls,
        connection: sqlite3.Connection,
        decision_id: UUID,
        project_id: UUID,
        status: ApprovalResolutionStatus,
        resolved_by: str,
        resolved_at: datetime,
    ) -> ApprovalRecord:
        result = connection.execute(
            """
            UPDATE approval_requests
            SET
                status = ?,
                resolved_at = ?,
                resolved_by = ?
            WHERE decision_id = ?
            AND status = 'PENDING'
            AND (
                expires_at IS NULL
                OR expires_at > ?
            )
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
                resolved_at.isoformat(),
                str(project_id),
            ),
        )

        if result.rowcount == 0:
            current_approval = cls.get_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
            )

            if current_approval is None:
                raise ApprovalNotFoundError(decision_id)

            if (
                current_approval.status == "PENDING"
                and current_approval.expires_at is not None
                and current_approval.expires_at <= resolved_at
            ):
                raise ApprovalExpiredError(decision_id)

            raise ApprovalAlreadyResolvedError(
                decision_id=decision_id,
                current_status=current_approval.status,
            )

        resolved = cls.get_with_connection(
            connection=connection,
            decision_id=decision_id,
            project_id=project_id,
        )

        if resolved is None:
            raise ApprovalNotFoundError(decision_id)

        return resolved

    @classmethod
    def expire_due_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        expired_at: datetime,
        resolved_by: str = "decaustrum-expiration",
    ) -> list[tuple[ApprovalRecord, ApprovalRecord]]:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT approval_requests.*
            FROM approval_requests
            JOIN authorization_decisions
                ON authorization_decisions.decision_id
                = approval_requests.decision_id
            WHERE authorization_decisions.project_id = ?
            AND approval_requests.status = 'PENDING'
            AND approval_requests.expires_at IS NOT NULL
            AND approval_requests.expires_at <= ?
            ORDER BY approval_requests.expires_at,
                     approval_requests.decision_id
            """,
            (
                str(project_id),
                expired_at.isoformat(),
            ),
        ).fetchall()
        expired: list[
            tuple[ApprovalRecord, ApprovalRecord]
        ] = []

        for row in rows:
            previous = cls._row_to_approval(row)
            result = connection.execute(
                """
                UPDATE approval_requests
                SET
                    status = 'EXPIRED',
                    resolved_at = ?,
                    resolved_by = ?
                WHERE decision_id = ?
                AND status = 'PENDING'
                AND expires_at IS NOT NULL
                AND expires_at <= ?
                """,
                (
                    expired_at.isoformat(),
                    resolved_by,
                    str(previous.decision_id),
                    expired_at.isoformat(),
                ),
            )

            if result.rowcount == 0:
                continue

            current = cls.get_with_connection(
                connection=connection,
                decision_id=previous.decision_id,
                project_id=project_id,
            )

            if current is not None:
                expired.append((previous, current))

        return expired

    def resolve(
        self,
        decision_id: UUID,
        project_id: UUID,
        status: ApprovalResolutionStatus,
        resolved_by: str,
        resolved_at: datetime,
    ) -> ApprovalRecord:
        with self.database.connect() as connection:
            return self.resolve_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
                status=status,
                resolved_by=resolved_by,
                resolved_at=resolved_at,
            )

    def list(
        self,
        project_id: UUID,
        status: ApprovalStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ApprovalRecord]:
        with self.database.connect() as connection:
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

    def count(
        self,
        project_id: UUID,
        status: ApprovalStatus | None = None,
    ) -> int:
        with self.database.connect() as connection:
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

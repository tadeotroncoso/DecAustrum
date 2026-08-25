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
)


CREATE_DECISIONS_TABLE = """
CREATE TABLE IF NOT EXISTS authorization_decisions (
    decision_id TEXT PRIMARY KEY,
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
    idempotency_key TEXT PRIMARY KEY,
    request_fingerprint TEXT NOT NULL,
    decision_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    FOREIGN KEY (decision_id)
        REFERENCES authorization_decisions(decision_id)
)
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

    def initialize(self) -> None:
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self._connect() as connection:
            connection.execute(CREATE_DECISIONS_TABLE)
            self._migrate_decisions_table(connection)
            connection.execute(CREATE_APPROVAL_REQUESTS_TABLE)
            connection.execute(CREATE_APPROVAL_REQUESTS_TABLE)
            connection.execute(CREATE_IDEMPOTENCY_RECORDS_TABLE)

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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(authorization.decision_id),
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
    ) -> AuthorizationResponse | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT *
                FROM authorization_decisions
                WHERE decision_id = ?
                """,
                (str(decision_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_authorization(row)

    def get_idempotency_record(
        self,
        idempotency_key: str,
    ) -> IdempotencyRecord | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT
                    idempotency_key,
                    request_fingerprint,
                    decision_id,
                    created_at
                FROM idempotency_records
                WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()

        if row is None:
            return None

        return IdempotencyRecord.model_validate(
            {
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
        limit: int = 20,
        offset: int = 0,
    ) -> list[AuthorizationResponse]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT *
                FROM authorization_decisions
                ORDER BY evaluated_at DESC, decision_id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        return [
            self._row_to_authorization(row)
            for row in rows
        ]

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM authorization_decisions
                """
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
    ) -> ApprovalRecord | None:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT *
                FROM approval_requests
                WHERE decision_id = ?
                """,
                (str(decision_id),),
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
                """,
                (
                    status,
                    resolved_at.isoformat(),
                    resolved_by,
                    str(decision_id),
                ),
            )

            if result.rowcount == 0:
                row = connection.execute(
                    """
                    SELECT *
                    FROM approval_requests
                    WHERE decision_id = ?
                    """,
                    (str(decision_id),),
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
                SELECT *
                FROM approval_requests
                WHERE decision_id = ?
                """,
                (str(decision_id),),
            ).fetchone()

        return self._row_to_approval(row)

    def list_approvals(
        self,
        status: ApprovalStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ApprovalRecord]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row

            if status is None:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM approval_requests
                    ORDER BY requested_at DESC, decision_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM approval_requests
                    WHERE status = ?
                    ORDER BY requested_at DESC, decision_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (status, limit, offset),
                ).fetchall()

        return [
            self._row_to_approval(row)
            for row in rows
        ]


    def count_approvals(
        self,
        status: ApprovalStatus | None = None,
    ) -> int:
        with self._connect() as connection:
            if status is None:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM approval_requests
                    """
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM approval_requests
                    WHERE status = ?
                    """,
                    (status,),
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
                idempotency_key,
                request_fingerprint,
                decision_id,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                record.idempotency_key,
                record.request_fingerprint,
                str(record.decision_id),
                record.created_at.isoformat(),
            ),
        )
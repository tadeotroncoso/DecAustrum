import json
import sqlite3
from pathlib import Path
from uuid import UUID

from app.approval_models import ApprovalRecord
from app.authorization_models import AuthorizationResponse


CREATE_DECISIONS_TABLE = """
CREATE TABLE IF NOT EXISTS authorization_decisions (
    decision_id TEXT PRIMARY KEY,
    evaluated_at TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_id TEXT,
    policy_version INTEGER,
    reason TEXT NOT NULL,
    evidence_json TEXT,
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

    def initialize(self) -> None:
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self._connect() as connection:
            connection.execute(CREATE_DECISIONS_TABLE)
            connection.execute(CREATE_APPROVAL_REQUESTS_TABLE)

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
                agent,
                action,
                context_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(authorization.decision_id),
                authorization.evaluated_at.isoformat(),
                authorization.decision,
                authorization.policy,
                authorization.policy_version,
                authorization.reason,
                evidence_json,
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

        return AuthorizationResponse.model_validate(
            {
                "decision_id": row["decision_id"],
                "evaluated_at": row["evaluated_at"],
                "decision": row["decision"],
                "policy": row["policy_id"],
                "policy_version": row["policy_version"],
                "reason": row["reason"],
                "evidence": evidence,
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
    ) -> None:
        with self._connect() as connection:
            self._insert_authorization(
                connection,
                authorization,
            )

            if approval is not None:
                if approval.decision_id != authorization.decision_id:
                    raise ValueError(
                        "Approval decision_id must match "
                        "authorization decision_id."
                    )

                self._insert_approval(
                    connection,
                    approval,
                )
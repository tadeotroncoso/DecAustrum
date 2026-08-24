import json
import sqlite3
from pathlib import Path
from uuid import UUID

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


class EvidenceStore:
    def __init__(
        self,
        database_path: Path,
    ) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with sqlite3.connect(self.database_path) as connection:
            connection.execute(CREATE_DECISIONS_TABLE)

    def save(
        self,
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

        with sqlite3.connect(self.database_path) as connection:
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
        with sqlite3.connect(self.database_path) as connection:
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
        with sqlite3.connect(self.database_path) as connection:
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
        with sqlite3.connect(self.database_path) as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM authorization_decisions
                """
            ).fetchone()

        return int(row[0])
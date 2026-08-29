import json
import sqlite3
from uuid import UUID

from app.authorization_models import AuthorizationResponse
from app.storage.database import SQLiteDatabase


class AuthorizationDecisionRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def insert(
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
                project_id,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(authorization.decision_id),
                str(authorization.project_id),
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
                "project_id": row["project_id"],
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

    def save(
        self,
        authorization: AuthorizationResponse,
    ) -> None:
        with self.database.connect() as connection:
            self.insert(connection, authorization)

    def get(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> AuthorizationResponse | None:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT *
                FROM authorization_decisions
                WHERE decision_id = ?
                AND project_id = ?
                """,
                (
                    str(decision_id),
                    str(project_id),
                ),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_authorization(row)

    def list(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[AuthorizationResponse]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT *
                FROM authorization_decisions
                WHERE project_id = ?
                ORDER BY evaluated_at DESC, decision_id DESC
                LIMIT ? OFFSET ?
                """,
                (
                    str(project_id),
                    limit,
                    offset,
                ),
            ).fetchall()

        return [
            self._row_to_authorization(row)
            for row in rows
        ]

    def count(self, project_id: UUID) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM authorization_decisions
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        return int(row[0])

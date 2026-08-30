import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from uuid import UUID

from app.evidence_models import (
    DecisionSearchFilters,
    EvidenceExportSnapshot,
)
from app.integrity_models import (
    DecisionIntegrityProof,
    VerifiableDecisionRecord,
)
from app.storage.database import SQLiteDatabase
from app.storage.decisions import (
    AuthorizationDecisionRepository,
)
from app.storage.integrity import DecisionIntegrityRepository


class EvidenceRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_record(
        row: sqlite3.Row,
    ) -> VerifiableDecisionRecord:
        decision = (
            AuthorizationDecisionRepository
            ._row_to_authorization(row)
        )
        integrity = DecisionIntegrityProof.model_validate(
            {
                "decision_id": row["decision_id"],
                "project_id": row["integrity_project_id"],
                "sequence_number": row["sequence_number"],
                "previous_hash": row["previous_hash"],
                "payload_hash": row["payload_hash"],
                "record_hash": row["record_hash"],
                "algorithm": row["algorithm"],
                "schema_version": row[
                    "integrity_schema_version"
                ],
                "created_at": row["integrity_created_at"],
            }
        )

        return VerifiableDecisionRecord(
            decision=decision,
            integrity=integrity,
        )

    @staticmethod
    def _record_query(
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        max_sequence_number: int,
    ) -> tuple[str, list[object]]:
        where_clause, parameters = (
            AuthorizationDecisionRepository._search_where(
                project_id,
                filters,
            )
        )
        where_clause += " AND i.sequence_number <= ?"
        parameters.append(max_sequence_number)
        direction = "ASC" if filters.sort == "asc" else "DESC"
        query = f"""
            SELECT
                d.*,
                i.project_id AS integrity_project_id,
                i.sequence_number,
                i.previous_hash,
                i.payload_hash,
                i.record_hash,
                i.algorithm,
                i.schema_version AS integrity_schema_version,
                i.created_at AS integrity_created_at
            FROM authorization_decisions AS d
            JOIN decision_integrity_records AS i
                ON i.decision_id = d.decision_id
                AND i.project_id = d.project_id
            LEFT JOIN approval_requests AS a
                ON a.decision_id = d.decision_id
            WHERE {where_clause}
            ORDER BY
                d.evaluated_at {direction},
                d.decision_id {direction}
        """  # nosec B608

        return query, parameters

    def create_snapshot(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
    ) -> EvidenceExportSnapshot:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            head = connection.execute(
                """
                SELECT sequence_number, record_hash
                FROM decision_integrity_records
                WHERE project_id = ?
                ORDER BY sequence_number DESC
                LIMIT 1
                """,
                (str(project_id),),
            ).fetchone()
            max_sequence_number = (
                int(head["sequence_number"])
                if head is not None
                else 0
            )
            head_hash = (
                head["record_hash"]
                if head is not None
                else None
            )
            where_clause, parameters = (
                AuthorizationDecisionRepository._search_where(
                    project_id,
                    filters,
                )
            )
            where_clause += " AND i.sequence_number <= ?"
            parameters.append(max_sequence_number)
            record_count = int(
                connection.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM authorization_decisions AS d
                    JOIN decision_integrity_records AS i
                        ON i.decision_id = d.decision_id
                        AND i.project_id = d.project_id
                    LEFT JOIN approval_requests AS a
                        ON a.decision_id = d.decision_id
                    WHERE {where_clause}
                    """,  # nosec B608
                    parameters,
                ).fetchone()[0]
            )

        return EvidenceExportSnapshot(
            project_id=project_id,
            captured_at=datetime.now(timezone.utc),
            max_sequence_number=max_sequence_number,
            chain_record_count=max_sequence_number,
            chain_head_hash=head_hash,
            record_count=record_count,
        )

    def capture_records(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        maximum_records: int,
    ) -> tuple[
        EvidenceExportSnapshot,
        list[VerifiableDecisionRecord],
    ]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            head = connection.execute(
                """
                SELECT sequence_number, record_hash
                FROM decision_integrity_records
                WHERE project_id = ?
                ORDER BY sequence_number DESC
                LIMIT 1
                """,
                (str(project_id),),
            ).fetchone()
            max_sequence_number = (
                int(head["sequence_number"])
                if head is not None
                else 0
            )
            head_hash = (
                head["record_hash"]
                if head is not None
                else None
            )
            where_clause, parameters = (
                AuthorizationDecisionRepository._search_where(
                    project_id,
                    filters,
                )
            )
            where_clause += " AND i.sequence_number <= ?"
            parameters.append(max_sequence_number)
            record_count = int(
                connection.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM authorization_decisions AS d
                    JOIN decision_integrity_records AS i
                        ON i.decision_id = d.decision_id
                        AND i.project_id = d.project_id
                    LEFT JOIN approval_requests AS a
                        ON a.decision_id = d.decision_id
                    WHERE {where_clause}
                    """,  # nosec B608
                    parameters,
                ).fetchone()[0]
            )
            snapshot = EvidenceExportSnapshot(
                project_id=project_id,
                captured_at=datetime.now(timezone.utc),
                max_sequence_number=max_sequence_number,
                chain_record_count=max_sequence_number,
                chain_head_hash=head_hash,
                record_count=record_count,
            )

            if record_count > maximum_records:
                return snapshot, []

            query, record_parameters = self._record_query(
                project_id=project_id,
                filters=filters,
                max_sequence_number=max_sequence_number,
            )
            rows = connection.execute(
                query,
                record_parameters,
            ).fetchall()

        return snapshot, [
            self._row_to_record(row)
            for row in rows
        ]

    def iter_records(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        max_sequence_number: int,
        batch_size: int = 100,
    ) -> Iterator[VerifiableDecisionRecord]:
        query, parameters = self._record_query(
            project_id=project_id,
            filters=filters,
            max_sequence_number=max_sequence_number,
        )

        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.execute(query, parameters)

            while True:
                rows = cursor.fetchmany(batch_size)

                if not rows:
                    break

                for row in rows:
                    yield self._row_to_record(row)

    def list_records(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        max_sequence_number: int,
    ) -> list[VerifiableDecisionRecord]:
        return list(
            self.iter_records(
                project_id=project_id,
                filters=filters,
                max_sequence_number=max_sequence_number,
            )
        )

    def list_chain(
        self,
        *,
        project_id: UUID,
        max_sequence_number: int,
    ) -> list[DecisionIntegrityProof]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT *
                FROM decision_integrity_records
                WHERE project_id = ?
                AND sequence_number <= ?
                ORDER BY sequence_number
                """,
                (
                    str(project_id),
                    max_sequence_number,
                ),
            ).fetchall()

        return [
            DecisionIntegrityRepository._row_to_proof(row)
            for row in rows
        ]


__all__ = ["EvidenceRepository"]

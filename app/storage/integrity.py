import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from uuid import UUID

from app.authorization_models import AuthorizationResponse
from app.exceptions import DecisionIntegrityMigrationError
from app.integrity import (
    INTEGRITY_ALGORITHM,
    INTEGRITY_SCHEMA_VERSION,
    build_decision_integrity_proof,
    calculate_authorization_payload_hash,
    calculate_integrity_record_hash,
)
from app.integrity_models import (
    DecisionIntegrityProof,
    DecisionIntegrityVerification,
    IntegrityVerificationFailure,
)
from app.storage.database import SQLiteDatabase
from app.storage.decisions import (
    AuthorizationDecisionRepository,
)


class DecisionIntegrityRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_proof(
        row: sqlite3.Row,
    ) -> DecisionIntegrityProof:
        return DecisionIntegrityProof.model_validate(
            {
                "decision_id": row["decision_id"],
                "project_id": row["project_id"],
                "sequence_number": row["sequence_number"],
                "previous_hash": row["previous_hash"],
                "payload_hash": row["payload_hash"],
                "record_hash": row["record_hash"],
                "algorithm": row["algorithm"],
                "schema_version": row["schema_version"],
                "created_at": row["created_at"],
            }
        )

    @staticmethod
    def _insert_proof(
        connection: sqlite3.Connection,
        proof: DecisionIntegrityProof,
    ) -> None:
        connection.execute(
            """
            INSERT INTO decision_integrity_records (
                decision_id,
                project_id,
                sequence_number,
                previous_hash,
                payload_hash,
                record_hash,
                algorithm,
                schema_version,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(proof.decision_id),
                str(proof.project_id),
                proof.sequence_number,
                proof.previous_hash,
                proof.payload_hash,
                proof.record_hash,
                proof.algorithm,
                proof.schema_version,
                proof.created_at.isoformat(),
            ),
        )

    def insert(
        self,
        connection: sqlite3.Connection,
        authorization: AuthorizationResponse,
    ) -> DecisionIntegrityProof:
        connection.row_factory = sqlite3.Row

        previous_row = connection.execute(
            """
            SELECT sequence_number, record_hash
            FROM decision_integrity_records
            WHERE project_id = ?
            ORDER BY sequence_number DESC
            LIMIT 1
            """,
            (str(authorization.project_id),),
        ).fetchone()

        sequence_number = 1
        previous_hash = None

        if previous_row is not None:
            sequence_number = (
                int(previous_row["sequence_number"]) + 1
            )
            previous_hash = previous_row["record_hash"]

        proof = build_decision_integrity_proof(
            authorization=authorization,
            sequence_number=sequence_number,
            previous_hash=previous_hash,
        )
        self._insert_proof(connection, proof)

        return proof

    def backfill_existing_decisions(self) -> None:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            projects = connection.execute(
                """
                SELECT project_id, COUNT(*) AS decision_count
                FROM authorization_decisions
                GROUP BY project_id
                ORDER BY project_id
                """
            )

            for project_row in projects:
                project_id = UUID(project_row["project_id"])
                decision_count = int(
                    project_row["decision_count"]
                )
                integrity_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*)
                        FROM decision_integrity_records
                        WHERE project_id = ?
                        """,
                        (str(project_id),),
                    ).fetchone()[0]
                )

                if integrity_count == decision_count:
                    continue

                if integrity_count != 0:
                    raise DecisionIntegrityMigrationError(
                        project_id=project_id,
                        decision_count=decision_count,
                        integrity_count=integrity_count,
                    )

                decision_rows = connection.execute(
                    """
                    SELECT *
                    FROM authorization_decisions
                    WHERE project_id = ?
                    ORDER BY evaluated_at, decision_id
                    """,
                    (str(project_id),),
                )

                previous_hash = None

                for sequence_number, row in enumerate(
                    decision_rows,
                    start=1,
                ):
                    authorization = (
                        AuthorizationDecisionRepository
                        ._row_to_authorization(row)
                    )
                    proof = build_decision_integrity_proof(
                        authorization=authorization,
                        sequence_number=sequence_number,
                        previous_hash=previous_hash,
                    )
                    self._insert_proof(connection, proof)
                    previous_hash = proof.record_hash

    def get(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> DecisionIntegrityProof | None:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            row = connection.execute(
                """
                SELECT *
                FROM decision_integrity_records
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

        return self._row_to_proof(row)

    def list(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[DecisionIntegrityProof]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row

            rows = connection.execute(
                """
                SELECT *
                FROM decision_integrity_records
                WHERE project_id = ?
                ORDER BY sequence_number DESC
                LIMIT ? OFFSET ?
                """,
                (
                    str(project_id),
                    limit,
                    offset,
                ),
            ).fetchall()

        return [self._row_to_proof(row) for row in rows]

    def count(self, project_id: UUID) -> int:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*)
                FROM decision_integrity_records
                WHERE project_id = ?
                """,
                (str(project_id),),
            ).fetchone()

        return int(row[0])

    @staticmethod
    def _failed_verification(
        *,
        project_id: UUID,
        total_decisions: int,
        checked_records: int,
        failure: IntegrityVerificationFailure,
        head_hash: str | None = None,
    ) -> DecisionIntegrityVerification:
        return DecisionIntegrityVerification(
            project_id=project_id,
            verified=False,
            total_decisions=total_decisions,
            checked_records=checked_records,
            head_hash=head_hash,
            verified_at=datetime.now(timezone.utc),
            failure=failure,
        )

    def _iter_verification_rows(
        self,
        project_id: UUID,
        max_sequence_number: int,
    ) -> Iterator[sqlite3.Row]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            cursor = connection.execute(
                """
                SELECT
                    d.*,
                    i.sequence_number,
                    i.previous_hash,
                    i.payload_hash,
                    i.record_hash,
                    i.algorithm,
                    i.schema_version,
                    i.created_at AS integrity_created_at
                FROM decision_integrity_records AS i
                JOIN authorization_decisions AS d
                    ON d.decision_id = i.decision_id
                    AND d.project_id = i.project_id
                WHERE i.project_id = ?
                AND i.sequence_number <= ?
                ORDER BY i.sequence_number
                """,
                (str(project_id), max_sequence_number),
            )

            for row in cursor:
                yield row

    def verify(
        self,
        project_id: UUID,
        expected_head_hash: str | None = None,
    ) -> DecisionIntegrityVerification:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            counts = connection.execute(
                """
                SELECT
                    (
                        SELECT COUNT(*)
                        FROM authorization_decisions
                        WHERE project_id = ?
                    ) AS decision_count,
                    (
                        SELECT COUNT(*)
                        FROM decision_integrity_records
                        WHERE project_id = ?
                    ) AS integrity_count,
                    COALESCE(
                        (
                            SELECT MAX(sequence_number)
                            FROM decision_integrity_records
                            WHERE project_id = ?
                        ),
                        0
                    ) AS max_sequence_number
                """,
                (
                    str(project_id),
                    str(project_id),
                    str(project_id),
                ),
            ).fetchone()
            total_decisions = int(counts["decision_count"])
            integrity_count = int(counts["integrity_count"])
            max_sequence_number = int(
                counts["max_sequence_number"]
            )
            unmatched_row = connection.execute(
                """
                SELECT d.decision_id
                FROM authorization_decisions AS d
                LEFT JOIN decision_integrity_records AS i
                    ON i.decision_id = d.decision_id
                    AND i.project_id = d.project_id
                WHERE d.project_id = ?
                AND i.decision_id IS NULL
                UNION ALL
                SELECT i.decision_id
                FROM decision_integrity_records AS i
                LEFT JOIN authorization_decisions AS d
                    ON d.decision_id = i.decision_id
                    AND d.project_id = i.project_id
                WHERE i.project_id = ?
                AND d.decision_id IS NULL
                LIMIT 1
                """,
                (str(project_id), str(project_id)),
            ).fetchone()

        if (
            integrity_count != total_decisions
            or unmatched_row is not None
        ):
            unmatched_id = (
                unmatched_row["decision_id"]
                if unmatched_row is not None
                else None
            )

            return self._failed_verification(
                project_id=project_id,
                total_decisions=total_decisions,
                checked_records=0,
                failure=IntegrityVerificationFailure(
                    code="record_count_mismatch",
                    message=(
                        "Decision and integrity record counts "
                        "do not match."
                    ),
                    decision_id=(
                        UUID(unmatched_id)
                        if unmatched_id is not None
                        else None
                    ),
                    expected=str(total_decisions),
                    actual=str(integrity_count),
                ),
            )

        previous_hash = None
        checked_records = 0
        expected_checkpoint_seen = expected_head_hash is None

        for expected_sequence, row in enumerate(
            self._iter_verification_rows(
                project_id,
                max_sequence_number,
            ),
            start=1,
        ):
            decision_id = UUID(row["decision_id"])
            actual_sequence = int(row["sequence_number"])

            if actual_sequence != expected_sequence:
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="sequence_mismatch",
                        message=(
                            "Integrity sequence is not contiguous."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        expected=str(expected_sequence),
                        actual=str(actual_sequence),
                    ),
                )

            if row["previous_hash"] != previous_hash:
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="previous_hash_mismatch",
                        message=(
                            "Integrity record does not reference "
                            "the preceding record."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        expected=previous_hash,
                        actual=row["previous_hash"],
                    ),
                )

            if row["algorithm"] != INTEGRITY_ALGORITHM:
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="algorithm_mismatch",
                        message=(
                            "Integrity algorithm is not supported."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        expected=INTEGRITY_ALGORITHM,
                        actual=row["algorithm"],
                    ),
                )

            if (
                int(row["schema_version"])
                != INTEGRITY_SCHEMA_VERSION
            ):
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="schema_version_mismatch",
                        message=(
                            "Integrity schema version is not "
                            "supported."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        expected=str(INTEGRITY_SCHEMA_VERSION),
                        actual=str(row["schema_version"]),
                    ),
                )

            try:
                authorization = (
                    AuthorizationDecisionRepository
                    ._row_to_authorization(row)
                )
            except (KeyError, TypeError, ValueError) as exc:
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="payload_unreadable",
                        message=(
                            "Stored authorization payload cannot "
                            "be reconstructed."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        actual=type(exc).__name__,
                    ),
                )

            try:
                integrity_created_at = datetime.fromisoformat(
                    row["integrity_created_at"]
                )
            except (TypeError, ValueError):
                integrity_created_at = None

            if integrity_created_at != authorization.evaluated_at:
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="created_at_mismatch",
                        message=(
                            "Integrity timestamp does not match "
                            "the decision timestamp."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        expected=(
                            authorization.evaluated_at.isoformat()
                        ),
                        actual=row["integrity_created_at"],
                    ),
                )

            expected_payload_hash = (
                calculate_authorization_payload_hash(
                    authorization
                )
            )

            if row["payload_hash"] != expected_payload_hash:
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="payload_hash_mismatch",
                        message=(
                            "Authorization payload has changed."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        expected=expected_payload_hash,
                        actual=row["payload_hash"],
                    ),
                )

            expected_record_hash = calculate_integrity_record_hash(
                authorization=authorization,
                sequence_number=expected_sequence,
                previous_hash=previous_hash,
                payload_hash=expected_payload_hash,
            )

            if row["record_hash"] != expected_record_hash:
                return self._failed_verification(
                    project_id=project_id,
                    total_decisions=total_decisions,
                    checked_records=checked_records,
                    failure=IntegrityVerificationFailure(
                        code="record_hash_mismatch",
                        message=(
                            "Integrity record hash is invalid."
                        ),
                        decision_id=decision_id,
                        sequence_number=expected_sequence,
                        expected=expected_record_hash,
                        actual=row["record_hash"],
                    ),
                )

            previous_hash = row["record_hash"]
            if row["record_hash"] == expected_head_hash:
                expected_checkpoint_seen = True
            checked_records += 1

        if (
            expected_head_hash is not None
            and not expected_checkpoint_seen
        ):
            return self._failed_verification(
                project_id=project_id,
                total_decisions=total_decisions,
                checked_records=checked_records,
                head_hash=previous_hash,
                failure=IntegrityVerificationFailure(
                    code="head_hash_mismatch",
                    message=(
                        "Expected chain checkpoint is not "
                        "present in the current chain."
                    ),
                    expected=expected_head_hash,
                    actual=previous_hash,
                ),
            )

        return DecisionIntegrityVerification(
            project_id=project_id,
            verified=True,
            total_decisions=total_decisions,
            checked_records=checked_records,
            head_hash=previous_hash,
            verified_at=datetime.now(timezone.utc),
            failure=None,
        )

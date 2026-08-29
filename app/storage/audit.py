import json
import sqlite3
from datetime import datetime, timezone
from uuid import UUID

from app.audit_models import (
    AdministrativeAuditEvent,
    AuditAction,
    AuditActorType,
    AuditResourceType,
)
from app.storage.database import SQLiteDatabase


class AdministrativeAuditRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_event(
        row: sqlite3.Row,
    ) -> AdministrativeAuditEvent:
        return AdministrativeAuditEvent.model_validate(
            {
                "event_id": row["event_id"],
                "occurred_at": row["occurred_at"],
                "project_id": row["project_id"],
                "actor_type": row["actor_type"],
                "actor_id": row["actor_id"],
                "action": row["action"],
                "resource_type": row["resource_type"],
                "resource_id": row["resource_id"],
                "reason": row["reason"],
                "before": (
                    json.loads(row["before_json"])
                    if row["before_json"] is not None
                    else None
                ),
                "after": (
                    json.loads(row["after_json"])
                    if row["after_json"] is not None
                    else None
                ),
                "metadata": json.loads(row["metadata_json"]),
            }
        )

    @staticmethod
    def insert(
        connection: sqlite3.Connection,
        event: AdministrativeAuditEvent,
    ) -> None:
        connection.execute(
            """
            INSERT INTO administrative_audit_events (
                event_id,
                occurred_at,
                project_id,
                actor_type,
                actor_id,
                action,
                resource_type,
                resource_id,
                reason,
                before_json,
                after_json,
                metadata_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(event.event_id),
                event.occurred_at.isoformat(),
                str(event.project_id),
                event.actor_type,
                event.actor_id,
                event.action,
                event.resource_type,
                event.resource_id,
                event.reason,
                (
                    json.dumps(
                        event.before,
                        sort_keys=True,
                    )
                    if event.before is not None
                    else None
                ),
                (
                    json.dumps(
                        event.after,
                        sort_keys=True,
                    )
                    if event.after is not None
                    else None
                ),
                json.dumps(event.metadata, sort_keys=True),
            ),
        )

    @staticmethod
    def _filters(
        *,
        project_id: UUID | None,
        action: AuditAction | None,
        resource_type: AuditResourceType | None,
        resource_id: str | None,
        actor_type: AuditActorType | None,
        actor_id: str | None,
        occurred_after: datetime | None,
        occurred_before: datetime | None,
    ) -> tuple[str, list[object]]:
        clauses: list[str] = []
        parameters: list[object] = []

        if project_id is not None:
            clauses.append("project_id = ?")
            parameters.append(str(project_id))

        if action is not None:
            clauses.append("action = ?")
            parameters.append(action)

        if resource_type is not None:
            clauses.append("resource_type = ?")
            parameters.append(resource_type)

        if resource_id is not None:
            clauses.append("resource_id = ?")
            parameters.append(resource_id)

        if actor_type is not None:
            clauses.append("actor_type = ?")
            parameters.append(actor_type)

        if actor_id is not None:
            clauses.append("actor_id = ?")
            parameters.append(actor_id)

        if occurred_after is not None:
            clauses.append("occurred_at >= ?")
            parameters.append(
                occurred_after.astimezone(
                    timezone.utc
                ).isoformat()
            )

        if occurred_before is not None:
            clauses.append("occurred_at <= ?")
            parameters.append(
                occurred_before.astimezone(
                    timezone.utc
                ).isoformat()
            )

        where_clause = ""

        if clauses:
            where_clause = "WHERE " + " AND ".join(clauses)

        return where_clause, parameters

    def get(
        self,
        event_id: UUID,
    ) -> AdministrativeAuditEvent | None:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM administrative_audit_events
                WHERE event_id = ?
                """,
                (str(event_id),),
            ).fetchone()

        if row is None:
            return None

        return self._row_to_event(row)

    def list(
        self,
        *,
        project_id: UUID | None = None,
        action: AuditAction | None = None,
        resource_type: AuditResourceType | None = None,
        resource_id: str | None = None,
        actor_type: AuditActorType | None = None,
        actor_id: str | None = None,
        occurred_after: datetime | None = None,
        occurred_before: datetime | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[AdministrativeAuditEvent]:
        where_clause, parameters = self._filters(
            project_id=project_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_after=occurred_after,
            occurred_before=occurred_before,
        )
        parameters.extend([limit, offset])

        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"""
                SELECT *
                FROM administrative_audit_events
                {where_clause}
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT ? OFFSET ?
                """,
                parameters,
            ).fetchall()

        return [self._row_to_event(row) for row in rows]

    def count(
        self,
        *,
        project_id: UUID | None = None,
        action: AuditAction | None = None,
        resource_type: AuditResourceType | None = None,
        resource_id: str | None = None,
        actor_type: AuditActorType | None = None,
        actor_id: str | None = None,
        occurred_after: datetime | None = None,
        occurred_before: datetime | None = None,
    ) -> int:
        where_clause, parameters = self._filters(
            project_id=project_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_after=occurred_after,
            occurred_before=occurred_before,
        )

        with self.database.connect() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM administrative_audit_events
                {where_clause}
                """,
                parameters,
            ).fetchone()

        return int(row[0])

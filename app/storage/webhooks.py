import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.exceptions import (
    WebhookDeliveryNotFoundError,
    WebhookDeliveryNotRedeliverableError,
    WebhookDeliveryStateError,
    WebhookSubscriptionDisabledError,
    WebhookSubscriptionNotFoundError,
)
from app.storage.database import SQLiteDatabase
from app.webhook_models import (
    WebhookDelivery,
    WebhookDeliveryAttempt,
    WebhookDeliveryOutcome,
    WebhookDeliveryStatus,
    WebhookEvent,
    WebhookEventType,
    WebhookSubscription,
    WebhookSubscriptionStatus,
)
from app.webhooks import canonical_webhook_payload


@dataclass(frozen=True)
class WebhookDispatchItem:
    delivery: WebhookDelivery
    event: WebhookEvent
    subscription: WebhookSubscription
    payload: bytes


class WebhookRepository:
    def __init__(self, database: SQLiteDatabase) -> None:
        self.database = database

    @staticmethod
    def _row_to_subscription(
        row: sqlite3.Row,
    ) -> WebhookSubscription:
        return WebhookSubscription.model_validate(
            {
                "subscription_id": row["subscription_id"],
                "project_id": row["project_id"],
                "url": row["url"],
                "event_types": json.loads(
                    row["event_types_json"]
                ),
                "status": row["status"],
                "secret_version": row["secret_version"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "disabled_at": row["disabled_at"],
            }
        )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> WebhookEvent:
        return WebhookEvent.model_validate(
            json.loads(row["payload_json"])
        )

    @staticmethod
    def _row_to_delivery(
        row: sqlite3.Row,
    ) -> WebhookDelivery:
        return WebhookDelivery.model_validate(
            {
                "delivery_id": row["delivery_id"],
                "event_id": row["event_id"],
                "subscription_id": row["subscription_id"],
                "project_id": row["project_id"],
                "status": row["status"],
                "attempt_count": row["attempt_count"],
                "failure_count": row["failure_count"],
                "redelivery_count": row["redelivery_count"],
                "next_attempt_at": row["next_attempt_at"],
                "lease_expires_at": row["lease_expires_at"],
                "delivered_at": row["delivered_at"],
                "last_attempt_at": row["last_attempt_at"],
                "last_status_code": row["last_status_code"],
                "last_error": row["last_error"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )

    @staticmethod
    def _row_to_attempt(
        row: sqlite3.Row,
    ) -> WebhookDeliveryAttempt:
        return WebhookDeliveryAttempt.model_validate(
            {
                "attempt_id": row["attempt_id"],
                "delivery_id": row["delivery_id"],
                "attempt_number": row["attempt_number"],
                "attempted_at": row["attempted_at"],
                "completed_at": row["completed_at"],
                "outcome": row["outcome"],
                "status_code": row["status_code"],
                "error": row["error"],
            }
        )

    @staticmethod
    def insert_subscription(
        connection: sqlite3.Connection,
        subscription: WebhookSubscription,
    ) -> None:
        connection.execute(
            """
            INSERT INTO webhook_subscriptions (
                subscription_id,
                project_id,
                url,
                event_types_json,
                status,
                secret_version,
                created_at,
                updated_at,
                disabled_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(subscription.subscription_id),
                str(subscription.project_id),
                subscription.url,
                json.dumps(
                    subscription.event_types,
                    sort_keys=True,
                ),
                subscription.status,
                subscription.secret_version,
                subscription.created_at.isoformat(),
                subscription.updated_at.isoformat(),
                (
                    subscription.disabled_at.isoformat()
                    if subscription.disabled_at is not None
                    else None
                ),
            ),
        )

    @classmethod
    def get_subscription_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        subscription_id: UUID,
    ) -> WebhookSubscription | None:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM webhook_subscriptions
            WHERE project_id = ?
            AND subscription_id = ?
            """,
            (str(project_id), str(subscription_id)),
        ).fetchone()

        if row is None:
            return None

        return cls._row_to_subscription(row)

    def get_subscription(
        self,
        project_id: UUID,
        subscription_id: UUID,
    ) -> WebhookSubscription | None:
        with self.database.connect() as connection:
            return self.get_subscription_with_connection(
                connection=connection,
                project_id=project_id,
                subscription_id=subscription_id,
            )

    @staticmethod
    def _subscription_filters(
        project_id: UUID,
        status: WebhookSubscriptionStatus | None,
    ) -> tuple[str, list[object]]:
        clauses = ["project_id = ?"]
        parameters: list[object] = [str(project_id)]

        if status is not None:
            clauses.append("status = ?")
            parameters.append(status)

        return " AND ".join(clauses), parameters

    def list_subscriptions(
        self,
        project_id: UUID,
        status: WebhookSubscriptionStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookSubscription]:
        where_clause, parameters = self._subscription_filters(
            project_id,
            status,
        )
        parameters.extend([limit, offset])

        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"""
                SELECT *
                FROM webhook_subscriptions
                WHERE {where_clause}
                ORDER BY created_at DESC, subscription_id DESC
                LIMIT ? OFFSET ?
                """,
                parameters,
            ).fetchall()

        return [
            self._row_to_subscription(row)
            for row in rows
        ]

    def count_subscriptions(
        self,
        project_id: UUID,
        status: WebhookSubscriptionStatus | None = None,
    ) -> int:
        where_clause, parameters = self._subscription_filters(
            project_id,
            status,
        )

        with self.database.connect() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM webhook_subscriptions
                WHERE {where_clause}
                """,
                parameters,
            ).fetchone()

        return int(row[0])

    @classmethod
    def disable_subscription_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        subscription_id: UUID,
        disabled_at: datetime,
    ) -> WebhookSubscription:
        current = cls.get_subscription_with_connection(
            connection=connection,
            project_id=project_id,
            subscription_id=subscription_id,
        )

        if current is None:
            raise WebhookSubscriptionNotFoundError(
                project_id,
                subscription_id,
            )

        if current.status == "DISABLED":
            return current

        connection.execute(
            """
            UPDATE webhook_subscriptions
            SET
                status = 'DISABLED',
                updated_at = ?,
                disabled_at = ?
            WHERE project_id = ?
            AND subscription_id = ?
            AND status = 'ACTIVE'
            """,
            (
                disabled_at.isoformat(),
                disabled_at.isoformat(),
                str(project_id),
                str(subscription_id),
            ),
        )
        connection.execute(
            """
            UPDATE webhook_deliveries
            SET
                status = 'CANCELLED',
                next_attempt_at = NULL,
                lease_expires_at = NULL,
                last_error = 'Webhook subscription was disabled.',
                updated_at = ?
            WHERE project_id = ?
            AND subscription_id = ?
            AND status IN ('PENDING', 'RETRY_SCHEDULED')
            """,
            (
                disabled_at.isoformat(),
                str(project_id),
                str(subscription_id),
            ),
        )

        updated = cls.get_subscription_with_connection(
            connection=connection,
            project_id=project_id,
            subscription_id=subscription_id,
        )

        if updated is None:
            raise WebhookSubscriptionNotFoundError(
                project_id,
                subscription_id,
            )

        return updated

    @classmethod
    def rotate_subscription_secret_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        subscription_id: UUID,
        rotated_at: datetime,
    ) -> WebhookSubscription:
        current = cls.get_subscription_with_connection(
            connection=connection,
            project_id=project_id,
            subscription_id=subscription_id,
        )

        if current is None:
            raise WebhookSubscriptionNotFoundError(
                project_id,
                subscription_id,
            )

        if current.status != "ACTIVE":
            raise WebhookSubscriptionDisabledError(subscription_id)

        connection.execute(
            """
            UPDATE webhook_subscriptions
            SET
                secret_version = secret_version + 1,
                updated_at = ?
            WHERE project_id = ?
            AND subscription_id = ?
            AND status = 'ACTIVE'
            """,
            (
                rotated_at.isoformat(),
                str(project_id),
                str(subscription_id),
            ),
        )

        updated = cls.get_subscription_with_connection(
            connection=connection,
            project_id=project_id,
            subscription_id=subscription_id,
        )

        if updated is None:
            raise WebhookSubscriptionNotFoundError(
                project_id,
                subscription_id,
            )

        return updated

    @classmethod
    def insert_event_with_deliveries(
        cls,
        connection: sqlite3.Connection,
        event: WebhookEvent,
    ) -> list[WebhookDelivery]:
        payload = canonical_webhook_payload(event)
        connection.execute(
            """
            INSERT INTO webhook_events (
                event_id,
                project_id,
                event_type,
                occurred_at,
                resource_type,
                resource_id,
                schema_version,
                payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(event.event_id),
                str(event.project_id),
                event.event_type,
                event.occurred_at.isoformat(),
                event.resource_type,
                event.resource_id,
                event.schema_version,
                payload.decode("utf-8"),
            ),
        )

        connection.row_factory = sqlite3.Row
        subscription_rows = connection.execute(
            """
            SELECT *
            FROM webhook_subscriptions
            WHERE project_id = ?
            AND status = 'ACTIVE'
            ORDER BY created_at, subscription_id
            """,
            (str(event.project_id),),
        ).fetchall()
        deliveries: list[WebhookDelivery] = []

        for row in subscription_rows:
            subscription = cls._row_to_subscription(row)

            if (
                "*" not in subscription.event_types
                and event.event_type
                not in subscription.event_types
            ):
                continue

            delivery = WebhookDelivery(
                delivery_id=uuid4(),
                event_id=event.event_id,
                subscription_id=subscription.subscription_id,
                project_id=event.project_id,
                status="PENDING",
                next_attempt_at=event.occurred_at,
                created_at=event.occurred_at,
                updated_at=event.occurred_at,
            )
            cls._insert_delivery(connection, delivery)
            deliveries.append(delivery)

        return deliveries

    @staticmethod
    def _insert_delivery(
        connection: sqlite3.Connection,
        delivery: WebhookDelivery,
    ) -> None:
        connection.execute(
            """
            INSERT INTO webhook_deliveries (
                delivery_id,
                event_id,
                subscription_id,
                project_id,
                status,
                attempt_count,
                failure_count,
                redelivery_count,
                next_attempt_at,
                lease_expires_at,
                delivered_at,
                last_attempt_at,
                last_status_code,
                last_error,
                created_at,
                updated_at
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                str(delivery.delivery_id),
                str(delivery.event_id),
                str(delivery.subscription_id),
                str(delivery.project_id),
                delivery.status,
                delivery.attempt_count,
                delivery.failure_count,
                delivery.redelivery_count,
                (
                    delivery.next_attempt_at.isoformat()
                    if delivery.next_attempt_at is not None
                    else None
                ),
                (
                    delivery.lease_expires_at.isoformat()
                    if delivery.lease_expires_at is not None
                    else None
                ),
                (
                    delivery.delivered_at.isoformat()
                    if delivery.delivered_at is not None
                    else None
                ),
                (
                    delivery.last_attempt_at.isoformat()
                    if delivery.last_attempt_at is not None
                    else None
                ),
                delivery.last_status_code,
                delivery.last_error,
                delivery.created_at.isoformat(),
                delivery.updated_at.isoformat(),
            ),
        )

    @classmethod
    def get_event_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        event_id: UUID,
    ) -> WebhookEvent | None:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM webhook_events
            WHERE project_id = ?
            AND event_id = ?
            """,
            (str(project_id), str(event_id)),
        ).fetchone()

        if row is None:
            return None

        return cls._row_to_event(row)

    def get_event(
        self,
        project_id: UUID,
        event_id: UUID,
    ) -> WebhookEvent | None:
        with self.database.connect() as connection:
            return self.get_event_with_connection(
                connection,
                project_id,
                event_id,
            )

    def list_events(
        self,
        project_id: UUID,
        event_type: WebhookEventType | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookEvent]:
        parameters: list[object] = [str(project_id)]
        event_filter = ""

        if event_type is not None:
            event_filter = "AND event_type = ?"
            parameters.append(event_type)

        parameters.extend([limit, offset])

        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"""
                SELECT *
                FROM webhook_events
                WHERE project_id = ?
                {event_filter}
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT ? OFFSET ?
                """,
                parameters,
            ).fetchall()

        return [self._row_to_event(row) for row in rows]

    def count_events(
        self,
        project_id: UUID,
        event_type: WebhookEventType | None = None,
    ) -> int:
        parameters: list[object] = [str(project_id)]
        event_filter = ""

        if event_type is not None:
            event_filter = "AND event_type = ?"
            parameters.append(event_type)

        with self.database.connect() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM webhook_events
                WHERE project_id = ?
                {event_filter}
                """,
                parameters,
            ).fetchone()

        return int(row[0])

    @classmethod
    def get_delivery_with_connection(
        cls,
        connection: sqlite3.Connection,
        project_id: UUID,
        delivery_id: UUID,
    ) -> WebhookDelivery | None:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT *
            FROM webhook_deliveries
            WHERE project_id = ?
            AND delivery_id = ?
            """,
            (str(project_id), str(delivery_id)),
        ).fetchone()

        if row is None:
            return None

        return cls._row_to_delivery(row)

    def get_delivery(
        self,
        project_id: UUID,
        delivery_id: UUID,
    ) -> WebhookDelivery | None:
        with self.database.connect() as connection:
            return self.get_delivery_with_connection(
                connection,
                project_id,
                delivery_id,
            )

    @staticmethod
    def _delivery_filters(
        *,
        project_id: UUID,
        status: WebhookDeliveryStatus | None,
        subscription_id: UUID | None,
        event_id: UUID | None,
    ) -> tuple[str, list[object]]:
        clauses = ["project_id = ?"]
        parameters: list[object] = [str(project_id)]

        for column, value in (
            ("status", status),
            ("subscription_id", subscription_id),
            ("event_id", event_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                parameters.append(str(value))

        return " AND ".join(clauses), parameters

    def list_deliveries(
        self,
        *,
        project_id: UUID,
        status: WebhookDeliveryStatus | None = None,
        subscription_id: UUID | None = None,
        event_id: UUID | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookDelivery]:
        where_clause, parameters = self._delivery_filters(
            project_id=project_id,
            status=status,
            subscription_id=subscription_id,
            event_id=event_id,
        )
        parameters.extend([limit, offset])

        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                f"""
                SELECT *
                FROM webhook_deliveries
                WHERE {where_clause}
                ORDER BY created_at DESC, delivery_id DESC
                LIMIT ? OFFSET ?
                """,
                parameters,
            ).fetchall()

        return [self._row_to_delivery(row) for row in rows]

    def count_deliveries(
        self,
        *,
        project_id: UUID,
        status: WebhookDeliveryStatus | None = None,
        subscription_id: UUID | None = None,
        event_id: UUID | None = None,
    ) -> int:
        where_clause, parameters = self._delivery_filters(
            project_id=project_id,
            status=status,
            subscription_id=subscription_id,
            event_id=event_id,
        )

        with self.database.connect() as connection:
            row = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM webhook_deliveries
                WHERE {where_clause}
                """,
                parameters,
            ).fetchone()

        return int(row[0])

    def list_attempts(
        self,
        delivery_id: UUID,
    ) -> list[WebhookDeliveryAttempt]:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """
                SELECT *
                FROM webhook_delivery_attempts
                WHERE delivery_id = ?
                ORDER BY attempt_number
                """,
                (str(delivery_id),),
            ).fetchall()

        return [self._row_to_attempt(row) for row in rows]

    def claim_due_deliveries(
        self,
        *,
        now: datetime,
        limit: int,
        lease_seconds: int,
    ) -> list[WebhookDelivery]:
        lease_expires_at = now + timedelta(
            seconds=lease_seconds
        )

        with self.database.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.row_factory = sqlite3.Row
            connection.execute(
                """
                UPDATE webhook_deliveries
                SET
                    status = 'CANCELLED',
                    lease_expires_at = NULL,
                    next_attempt_at = NULL,
                    last_error = 'Webhook subscription was disabled.',
                    updated_at = ?
                WHERE status = 'PROCESSING'
                AND lease_expires_at <= ?
                AND EXISTS (
                    SELECT 1
                    FROM webhook_subscriptions
                    WHERE webhook_subscriptions.subscription_id
                        = webhook_deliveries.subscription_id
                    AND webhook_subscriptions.status = 'DISABLED'
                )
                """,
                (now.isoformat(), now.isoformat()),
            )
            rows = connection.execute(
                """
                SELECT webhook_deliveries.delivery_id
                FROM webhook_deliveries
                JOIN webhook_subscriptions
                    ON webhook_subscriptions.subscription_id
                    = webhook_deliveries.subscription_id
                WHERE webhook_subscriptions.status = 'ACTIVE'
                AND (
                    (
                        webhook_deliveries.status IN (
                            'PENDING',
                            'RETRY_SCHEDULED'
                        )
                        AND webhook_deliveries.next_attempt_at <= ?
                    )
                    OR (
                        webhook_deliveries.status = 'PROCESSING'
                        AND webhook_deliveries.lease_expires_at <= ?
                    )
                )
                ORDER BY
                    COALESCE(
                        webhook_deliveries.next_attempt_at,
                        webhook_deliveries.lease_expires_at
                    ),
                    webhook_deliveries.delivery_id
                LIMIT ?
                """,
                (
                    now.isoformat(),
                    now.isoformat(),
                    limit,
                ),
            ).fetchall()
            delivery_ids = [row[0] for row in rows]

            if not delivery_ids:
                return []

            placeholders = ", ".join(
                "?" for _ in delivery_ids
            )
            connection.execute(
                f"""
                UPDATE webhook_deliveries
                SET
                    status = 'PROCESSING',
                    lease_expires_at = ?,
                    updated_at = ?
                WHERE delivery_id IN ({placeholders})
                """,
                [
                    lease_expires_at.isoformat(),
                    now.isoformat(),
                    *delivery_ids,
                ],
            )
            claimed_rows = connection.execute(
                f"""
                SELECT *
                FROM webhook_deliveries
                WHERE delivery_id IN ({placeholders})
                ORDER BY created_at, delivery_id
                """,
                delivery_ids,
            ).fetchall()

        return [
            self._row_to_delivery(row)
            for row in claimed_rows
        ]

    def get_dispatch_item(
        self,
        delivery: WebhookDelivery,
    ) -> WebhookDispatchItem:
        with self.database.connect() as connection:
            connection.row_factory = sqlite3.Row
            event_row = connection.execute(
                """
                SELECT *
                FROM webhook_events
                WHERE event_id = ?
                AND project_id = ?
                """,
                (
                    str(delivery.event_id),
                    str(delivery.project_id),
                ),
            ).fetchone()
            subscription_row = connection.execute(
                """
                SELECT *
                FROM webhook_subscriptions
                WHERE subscription_id = ?
                AND project_id = ?
                """,
                (
                    str(delivery.subscription_id),
                    str(delivery.project_id),
                ),
            ).fetchone()

        if event_row is None or subscription_row is None:
            raise RuntimeError(
                "Webhook delivery references missing data."
            )

        return WebhookDispatchItem(
            delivery=delivery,
            event=self._row_to_event(event_row),
            subscription=self._row_to_subscription(
                subscription_row
            ),
            payload=event_row["payload_json"].encode("utf-8"),
        )

    def cancel_processing_delivery(
        self,
        *,
        project_id: UUID,
        delivery_id: UUID,
        cancelled_at: datetime,
        reason: str,
    ) -> WebhookDelivery:
        with self.database.connect() as connection:
            connection.execute(
                """
                UPDATE webhook_deliveries
                SET
                    status = 'CANCELLED',
                    next_attempt_at = NULL,
                    lease_expires_at = NULL,
                    last_error = ?,
                    updated_at = ?
                WHERE project_id = ?
                AND delivery_id = ?
                AND status = 'PROCESSING'
                """,
                (
                    reason[:1000],
                    cancelled_at.isoformat(),
                    str(project_id),
                    str(delivery_id),
                ),
            )
            cancelled = self.get_delivery_with_connection(
                connection,
                project_id,
                delivery_id,
            )

        if cancelled is None:
            raise WebhookDeliveryNotFoundError(
                project_id,
                delivery_id,
            )

        return cancelled

    def record_delivery_result(
        self,
        *,
        project_id: UUID,
        delivery_id: UUID,
        attempted_at: datetime,
        completed_at: datetime,
        outcome: WebhookDeliveryOutcome,
        status_code: int | None,
        error: str | None,
        max_attempts: int,
        base_retry_seconds: int,
        max_retry_seconds: int,
    ) -> WebhookDelivery:
        with self.database.connect() as connection:
            current = self.get_delivery_with_connection(
                connection,
                project_id,
                delivery_id,
            )

            if current is None:
                raise WebhookDeliveryNotFoundError(
                    project_id,
                    delivery_id,
                )

            if current.status != "PROCESSING":
                raise WebhookDeliveryStateError(
                    delivery_id,
                    current.status,
                )

            attempt_number = current.attempt_count + 1
            normalized_error = (
                error[:1000]
                if error is not None
                else None
            )
            connection.execute(
                """
                INSERT INTO webhook_delivery_attempts (
                    attempt_id,
                    delivery_id,
                    attempt_number,
                    attempted_at,
                    completed_at,
                    outcome,
                    status_code,
                    error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    str(delivery_id),
                    attempt_number,
                    attempted_at.isoformat(),
                    completed_at.isoformat(),
                    outcome,
                    status_code,
                    normalized_error,
                ),
            )

            if outcome == "SUCCESS":
                new_status: WebhookDeliveryStatus = "DELIVERED"
                failure_count = 0
                next_attempt_at = None
                delivered_at = completed_at
            else:
                subscription = (
                    self.get_subscription_with_connection(
                        connection,
                        project_id,
                        current.subscription_id,
                    )
                )
                failure_count = current.failure_count + 1
                delivered_at = None

                if (
                    subscription is None
                    or subscription.status == "DISABLED"
                ):
                    new_status = "CANCELLED"
                    next_attempt_at = None
                elif failure_count >= max_attempts:
                    new_status = "DEAD_LETTER"
                    next_attempt_at = None
                else:
                    new_status = "RETRY_SCHEDULED"
                    retry_seconds = min(
                        base_retry_seconds
                        * (2 ** (failure_count - 1)),
                        max_retry_seconds,
                    )
                    next_attempt_at = completed_at + timedelta(
                        seconds=retry_seconds
                    )

            connection.execute(
                """
                UPDATE webhook_deliveries
                SET
                    status = ?,
                    attempt_count = ?,
                    failure_count = ?,
                    next_attempt_at = ?,
                    lease_expires_at = NULL,
                    delivered_at = ?,
                    last_attempt_at = ?,
                    last_status_code = ?,
                    last_error = ?,
                    updated_at = ?
                WHERE project_id = ?
                AND delivery_id = ?
                AND status = 'PROCESSING'
                """,
                (
                    new_status,
                    attempt_number,
                    failure_count,
                    (
                        next_attempt_at.isoformat()
                        if next_attempt_at is not None
                        else None
                    ),
                    (
                        delivered_at.isoformat()
                        if delivered_at is not None
                        else None
                    ),
                    completed_at.isoformat(),
                    status_code,
                    normalized_error,
                    completed_at.isoformat(),
                    str(project_id),
                    str(delivery_id),
                ),
            )
            updated = self.get_delivery_with_connection(
                connection,
                project_id,
                delivery_id,
            )

        if updated is None:
            raise WebhookDeliveryNotFoundError(
                project_id,
                delivery_id,
            )

        return updated

    @classmethod
    def request_redelivery_with_connection(
        cls,
        connection: sqlite3.Connection,
        *,
        project_id: UUID,
        delivery_id: UUID,
        requested_at: datetime,
    ) -> WebhookDelivery:
        current = cls.get_delivery_with_connection(
            connection,
            project_id,
            delivery_id,
        )

        if current is None:
            raise WebhookDeliveryNotFoundError(
                project_id,
                delivery_id,
            )

        if current.status != "DEAD_LETTER":
            raise WebhookDeliveryNotRedeliverableError(
                delivery_id,
                current.status,
            )

        subscription = cls.get_subscription_with_connection(
            connection,
            project_id,
            current.subscription_id,
        )

        if subscription is None:
            raise WebhookSubscriptionNotFoundError(
                project_id,
                current.subscription_id,
            )

        if subscription.status != "ACTIVE":
            raise WebhookSubscriptionDisabledError(
                subscription.subscription_id
            )

        connection.execute(
            """
            UPDATE webhook_deliveries
            SET
                status = 'PENDING',
                failure_count = 0,
                redelivery_count = redelivery_count + 1,
                next_attempt_at = ?,
                lease_expires_at = NULL,
                delivered_at = NULL,
                last_error = NULL,
                updated_at = ?
            WHERE project_id = ?
            AND delivery_id = ?
            AND status = 'DEAD_LETTER'
            """,
            (
                requested_at.isoformat(),
                requested_at.isoformat(),
                str(project_id),
                str(delivery_id),
            ),
        )
        updated = cls.get_delivery_with_connection(
            connection,
            project_id,
            delivery_id,
        )

        if updated is None:
            raise WebhookDeliveryNotFoundError(
                project_id,
                delivery_id,
            )

        return updated


__all__ = ["WebhookDispatchItem", "WebhookRepository"]

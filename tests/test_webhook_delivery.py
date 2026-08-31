import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.audit_models import AuditContext
from app.evidence_store import EvidenceStore
from app.project_models import Project
from app.services.webhooks import dispatch_pending_webhooks
from app.webhook_models import WebhookSubscription
from app.webhooks import (
    WebhookHttpResponse,
    WebhookTransportError,
    build_webhook_event,
    derive_webhook_signing_secret,
    verify_webhook_signature,
)

NOW = datetime(2026, 8, 29, 17, 0, tzinfo=timezone.utc)
MASTER_SECRET = "delivery-master-secret-value-12345"


class RecordingTransport:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def send(
        self,
        *,
        url,
        body,
        headers,
        timeout_seconds,
    ):
        self.requests.append(
            {
                "url": url,
                "body": body,
                "headers": headers,
                "timeout_seconds": timeout_seconds,
            }
        )
        outcome = self.outcomes.pop(0)

        if isinstance(outcome, Exception):
            raise outcome

        return WebhookHttpResponse(status_code=outcome)


def prepare_delivery(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    project = Project(
        project_id=uuid4(),
        name="Delivery Project",
        status="ACTIVE",
        created_at=NOW,
        updated_at=NOW,
    )
    store.save_project(project)
    subscription = WebhookSubscription(
        subscription_id=uuid4(),
        project_id=project.project_id,
        url="https://hooks.example.com/decaustrum",
        event_types=["authorization.created"],
        created_at=NOW,
        updated_at=NOW,
    )
    event = build_webhook_event(
        project_id=project.project_id,
        event_type="authorization.created",
        occurred_at=NOW,
        resource_type="AUTHORIZATION_DECISION",
        resource_id=str(uuid4()),
        data={"decision": "ALLOW"},
    )

    with store.database.connect() as connection:
        store.webhooks.insert_subscription(
            connection,
            subscription,
        )
        deliveries = (
            store.webhooks.insert_event_with_deliveries(
                connection,
                event,
            )
        )

    return store, project, subscription, event, deliveries[0]


def test_successful_dispatch_signs_and_records_attempt(tmp_path):
    store, project, subscription, event, delivery = (
        prepare_delivery(tmp_path)
    )
    transport = RecordingTransport([204])

    summary = dispatch_pending_webhooks(
        store=store,
        transport=transport,
        master_secret=MASTER_SECRET,
        now=NOW,
    )

    assert summary.model_dump() == {
        "claimed": 1,
        "delivered": 1,
        "retry_scheduled": 0,
        "dead_lettered": 0,
        "cancelled": 0,
    }
    stored = store.get_webhook_delivery(
        project.project_id,
        delivery.delivery_id,
    )
    attempts = store.list_webhook_delivery_attempts(
        delivery.delivery_id
    )
    request = transport.requests[0]
    signing_secret = derive_webhook_signing_secret(
        MASTER_SECRET,
        subscription.subscription_id,
        subscription.secret_version,
    )

    assert stored.status == "DELIVERED"
    assert stored.attempt_count == 1
    assert stored.delivered_at == NOW
    assert len(attempts) == 1
    assert attempts[0].outcome == "SUCCESS"
    assert attempts[0].status_code == 204
    assert request["headers"]["X-DecAustrum-Event-Id"] == str(
        event.event_id
    )
    assert verify_webhook_signature(
        payload=request["body"],
        timestamp=request["headers"]["X-DecAustrum-Timestamp"],
        signature=request["headers"]["X-DecAustrum-Signature"],
        signing_secret=signing_secret,
        now=NOW,
    )


def test_failed_delivery_retries_then_enters_dead_letter(
    tmp_path,
):
    store, project, _, _, delivery = prepare_delivery(tmp_path)
    transport = RecordingTransport([500, 503])

    first = dispatch_pending_webhooks(
        store=store,
        transport=transport,
        master_secret=MASTER_SECRET,
        now=NOW,
        max_attempts=2,
        base_retry_seconds=10,
    )
    scheduled = store.get_webhook_delivery(
        project.project_id,
        delivery.delivery_id,
    )

    assert first.retry_scheduled == 1
    assert scheduled.status == "RETRY_SCHEDULED"
    assert scheduled.next_attempt_at == NOW + timedelta(seconds=10)

    second = dispatch_pending_webhooks(
        store=store,
        transport=transport,
        master_secret=MASTER_SECRET,
        now=NOW + timedelta(seconds=10),
        max_attempts=2,
        base_retry_seconds=10,
    )
    dead = store.get_webhook_delivery(
        project.project_id,
        delivery.delivery_id,
    )
    attempts = store.list_webhook_delivery_attempts(
        delivery.delivery_id
    )

    assert second.dead_lettered == 1
    assert dead.status == "DEAD_LETTER"
    assert dead.attempt_count == 2
    assert dead.failure_count == 2
    assert [attempt.status_code for attempt in attempts] == [
        500,
        503,
    ]
    assert all(
        attempt.outcome == "HTTP_ERROR"
        for attempt in attempts
    )


def test_network_failure_is_recorded_without_http_status(tmp_path):
    store, project, _, _, delivery = prepare_delivery(tmp_path)
    transport = RecordingTransport(
        [WebhookTransportError("connection timed out")]
    )

    dispatch_pending_webhooks(
        store=store,
        transport=transport,
        master_secret=MASTER_SECRET,
        now=NOW,
    )

    stored = store.get_webhook_delivery(
        project.project_id,
        delivery.delivery_id,
    )
    attempt = store.list_webhook_delivery_attempts(
        delivery.delivery_id
    )[0]

    assert stored.status == "RETRY_SCHEDULED"
    assert stored.last_status_code is None
    assert attempt.outcome == "NETWORK_ERROR"
    assert attempt.error == "connection timed out"


def test_expired_processing_lease_can_be_reclaimed(tmp_path):
    store, _, _, _, delivery = prepare_delivery(tmp_path)

    first_claim = store.claim_due_webhook_deliveries(
        now=NOW,
        limit=10,
        lease_seconds=30,
    )
    early_claim = store.claim_due_webhook_deliveries(
        now=NOW + timedelta(seconds=29),
        limit=10,
        lease_seconds=30,
    )
    recovered_claim = store.claim_due_webhook_deliveries(
        now=NOW + timedelta(seconds=30),
        limit=10,
        lease_seconds=30,
    )

    assert [item.delivery_id for item in first_claim] == [
        delivery.delivery_id
    ]
    assert early_claim == []
    assert [item.delivery_id for item in recovered_claim] == [
        delivery.delivery_id
    ]


def test_manual_redelivery_preserves_attempt_history(tmp_path):
    store, project, _, _, delivery = prepare_delivery(tmp_path)
    failing_transport = RecordingTransport([500])
    dispatch_pending_webhooks(
        store=store,
        transport=failing_transport,
        master_secret=MASTER_SECRET,
        now=NOW,
        max_attempts=1,
    )
    context = AuditContext(
        actor_type="ADMIN",
        actor_id="operations-admin",
        reason="Receiver recovered after incident INC-42.",
    )

    queued = store.request_webhook_redelivery(
        project_id=project.project_id,
        delivery_id=delivery.delivery_id,
        requested_at=NOW + timedelta(minutes=1),
        audit_context=context,
    )

    assert queued.status == "PENDING"
    assert queued.attempt_count == 1
    assert queued.failure_count == 0
    assert queued.redelivery_count == 1

    success_transport = RecordingTransport([200])
    dispatch_pending_webhooks(
        store=store,
        transport=success_transport,
        master_secret=MASTER_SECRET,
        now=NOW + timedelta(minutes=1),
        max_attempts=1,
    )
    delivered = store.get_webhook_delivery(
        project.project_id,
        delivery.delivery_id,
    )
    attempts = store.list_webhook_delivery_attempts(
        delivery.delivery_id
    )

    assert delivered.status == "DELIVERED"
    assert delivered.attempt_count == 2
    assert [attempt.attempt_number for attempt in attempts] == [
        1,
        2,
    ]
    assert store.count_administrative_audit_events(
        project_id=project.project_id,
        action="WEBHOOK_REDELIVERY_REQUESTED",
    ) == 1


def test_delivery_attempts_are_immutable(tmp_path):
    store, _, _, _, delivery = prepare_delivery(tmp_path)
    dispatch_pending_webhooks(
        store=store,
        transport=RecordingTransport([200]),
        master_secret=MASTER_SECRET,
        now=NOW,
    )

    with sqlite3.connect(store.database_path) as connection:
        with pytest.raises(
            sqlite3.IntegrityError,
            match="webhook attempts are immutable",
        ):
            connection.execute(
                """
                UPDATE webhook_delivery_attempts
                SET outcome = 'HTTP_ERROR'
                WHERE delivery_id = ?
                """,
                (str(delivery.delivery_id),),
            )

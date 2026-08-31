from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException

from app.audit_models import AuditContext
from app.evidence_store import EvidenceStore
from app.exceptions import (
    WebhookDeliveryNotFoundError,
    WebhookDeliveryNotRedeliverableError,
    WebhookEventNotFoundError,
    WebhookSubscriptionDisabledError,
    WebhookSubscriptionNotFoundError,
)
from app.services.projects import get_project_or_404
from app.webhook_models import (
    WebhookDelivery,
    WebhookDeliveryDetail,
    WebhookDeliveryOutcome,
    WebhookDispatchSummary,
    WebhookEvent,
    WebhookSecretRotationResponse,
    WebhookSubscription,
    WebhookSubscriptionCreateRequest,
    WebhookSubscriptionProvisioningResponse,
)
from app.webhooks import (
    WebhookTransport,
    WebhookTransportError,
    build_webhook_headers,
    derive_webhook_signing_secret,
)

WEBHOOK_MAX_ATTEMPTS = 5
WEBHOOK_BASE_RETRY_SECONDS = 30
WEBHOOK_MAX_RETRY_SECONDS = 3600
WEBHOOK_LEASE_SECONDS = 30
WEBHOOK_REQUEST_TIMEOUT_SECONDS = 10.0


def _subscription_not_found(
    exc: WebhookSubscriptionNotFoundError,
) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "code": "webhook_subscription_not_found",
            "message": str(exc),
        },
    )


def _subscription_disabled(
    exc: WebhookSubscriptionDisabledError,
) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "webhook_subscription_disabled",
            "message": str(exc),
        },
    )


def get_webhook_subscription_or_404(
    *,
    project_id: UUID,
    subscription_id: UUID,
    store: EvidenceStore,
) -> WebhookSubscription:
    subscription = store.get_webhook_subscription(
        project_id,
        subscription_id,
    )

    if subscription is None:
        raise _subscription_not_found(
            WebhookSubscriptionNotFoundError(
                project_id,
                subscription_id,
            )
        )

    return subscription


def create_webhook_subscription(
    *,
    project_id: UUID,
    request: WebhookSubscriptionCreateRequest,
    master_secret: str,
    store: EvidenceStore,
    audit_context: AuditContext,
) -> WebhookSubscriptionProvisioningResponse:
    project = get_project_or_404(project_id, store)

    if project.status != "ACTIVE":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "project_disabled",
                "message": f"Project '{project_id}' is disabled.",
            },
        )

    created_at = datetime.now(timezone.utc)
    subscription = WebhookSubscription(
        subscription_id=uuid4(),
        project_id=project_id,
        url=request.url,
        event_types=request.event_types,
        created_at=created_at,
        updated_at=created_at,
    )
    store.save_webhook_subscription(
        subscription,
        audit_context,
    )

    return WebhookSubscriptionProvisioningResponse(
        subscription=subscription,
        signing_secret=derive_webhook_signing_secret(
            master_secret,
            subscription.subscription_id,
            subscription.secret_version,
        ),
    )


def disable_webhook_subscription(
    *,
    project_id: UUID,
    subscription_id: UUID,
    store: EvidenceStore,
    audit_context: AuditContext,
) -> WebhookSubscription:
    get_project_or_404(project_id, store)

    try:
        return store.disable_webhook_subscription(
            project_id=project_id,
            subscription_id=subscription_id,
            disabled_at=datetime.now(timezone.utc),
            audit_context=audit_context,
        )
    except WebhookSubscriptionNotFoundError as exc:
        raise _subscription_not_found(exc) from exc


def rotate_webhook_subscription_secret(
    *,
    project_id: UUID,
    subscription_id: UUID,
    master_secret: str,
    store: EvidenceStore,
    audit_context: AuditContext,
) -> WebhookSecretRotationResponse:
    get_project_or_404(project_id, store)

    try:
        subscription = store.rotate_webhook_secret(
            project_id=project_id,
            subscription_id=subscription_id,
            rotated_at=datetime.now(timezone.utc),
            audit_context=audit_context,
        )
    except WebhookSubscriptionNotFoundError as exc:
        raise _subscription_not_found(exc) from exc
    except WebhookSubscriptionDisabledError as exc:
        raise _subscription_disabled(exc) from exc

    return WebhookSecretRotationResponse(
        subscription=subscription,
        signing_secret=derive_webhook_signing_secret(
            master_secret,
            subscription.subscription_id,
            subscription.secret_version,
        ),
    )


def get_webhook_event_or_404(
    *,
    project_id: UUID,
    event_id: UUID,
    store: EvidenceStore,
) -> WebhookEvent:
    event = store.get_webhook_event(project_id, event_id)

    if event is None:
        exc = WebhookEventNotFoundError(project_id, event_id)
        raise HTTPException(
            status_code=404,
            detail={
                "code": "webhook_event_not_found",
                "message": str(exc),
            },
        )

    return event


def get_webhook_delivery_detail_or_404(
    *,
    project_id: UUID,
    delivery_id: UUID,
    store: EvidenceStore,
) -> WebhookDeliveryDetail:
    delivery = store.get_webhook_delivery(
        project_id,
        delivery_id,
    )

    if delivery is None:
        exc = WebhookDeliveryNotFoundError(
            project_id,
            delivery_id,
        )
        raise HTTPException(
            status_code=404,
            detail={
                "code": "webhook_delivery_not_found",
                "message": str(exc),
            },
        )

    event = get_webhook_event_or_404(
        project_id=project_id,
        event_id=delivery.event_id,
        store=store,
    )
    subscription = get_webhook_subscription_or_404(
        project_id=project_id,
        subscription_id=delivery.subscription_id,
        store=store,
    )

    return WebhookDeliveryDetail(
        delivery=delivery,
        event=event,
        subscription=subscription,
        attempts=store.list_webhook_delivery_attempts(
            delivery_id
        ),
    )


def request_webhook_redelivery(
    *,
    project_id: UUID,
    delivery_id: UUID,
    store: EvidenceStore,
    audit_context: AuditContext,
) -> WebhookDelivery:
    get_project_or_404(project_id, store)

    try:
        return store.request_webhook_redelivery(
            project_id=project_id,
            delivery_id=delivery_id,
            requested_at=datetime.now(timezone.utc),
            audit_context=audit_context,
        )
    except WebhookDeliveryNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "webhook_delivery_not_found",
                "message": str(exc),
            },
        ) from exc
    except WebhookDeliveryNotRedeliverableError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "webhook_delivery_not_redeliverable",
                "message": str(exc),
                "current_status": exc.current_status,
            },
        ) from exc
    except WebhookSubscriptionDisabledError as exc:
        raise _subscription_disabled(exc) from exc


def dispatch_pending_webhooks(
    *,
    store: EvidenceStore,
    transport: WebhookTransport,
    master_secret: str,
    limit: int = 20,
    now: datetime | None = None,
    max_attempts: int = WEBHOOK_MAX_ATTEMPTS,
    lease_seconds: int = WEBHOOK_LEASE_SECONDS,
    base_retry_seconds: int = WEBHOOK_BASE_RETRY_SECONDS,
    max_retry_seconds: int = WEBHOOK_MAX_RETRY_SECONDS,
    timeout_seconds: float = WEBHOOK_REQUEST_TIMEOUT_SECONDS,
) -> WebhookDispatchSummary:
    dispatch_time = now or datetime.now(timezone.utc)

    if dispatch_time.tzinfo is None:
        raise ValueError("Webhook dispatch time needs a timezone.")

    claimed = store.claim_due_webhook_deliveries(
        now=dispatch_time,
        limit=limit,
        lease_seconds=lease_seconds,
    )
    counters = {
        "delivered": 0,
        "retry_scheduled": 0,
        "dead_lettered": 0,
        "cancelled": 0,
    }

    for delivery in claimed:
        item = store.get_webhook_dispatch_item(delivery)

        if item.subscription.status != "ACTIVE":
            store.cancel_processing_webhook_delivery(
                project_id=delivery.project_id,
                delivery_id=delivery.delivery_id,
                cancelled_at=dispatch_time,
                reason="Webhook subscription was disabled.",
            )
            counters["cancelled"] += 1
            continue

        signing_secret = derive_webhook_signing_secret(
            master_secret,
            item.subscription.subscription_id,
            item.subscription.secret_version,
        )
        timestamp = int(dispatch_time.timestamp())
        headers = build_webhook_headers(
            event=item.event,
            delivery_id=delivery.delivery_id,
            payload=item.payload,
            timestamp=timestamp,
            signing_secret=signing_secret,
        )
        status_code = None
        error = None
        outcome: WebhookDeliveryOutcome

        try:
            response = transport.send(
                url=item.subscription.url,
                body=item.payload,
                headers=headers,
                timeout_seconds=timeout_seconds,
            )
            status_code = response.status_code

            if 200 <= status_code < 300:
                outcome = "SUCCESS"
            else:
                outcome = "HTTP_ERROR"
                error = (
                    f"Webhook endpoint returned HTTP "
                    f"{status_code}."
                )
        except WebhookTransportError as exc:
            outcome = "NETWORK_ERROR"
            error = str(exc)

        completed = store.record_webhook_delivery_result(
            project_id=delivery.project_id,
            delivery_id=delivery.delivery_id,
            attempted_at=dispatch_time,
            completed_at=dispatch_time,
            outcome=outcome,
            status_code=status_code,
            error=error,
            max_attempts=max_attempts,
            base_retry_seconds=base_retry_seconds,
            max_retry_seconds=max_retry_seconds,
        )

        if completed.status == "DELIVERED":
            counters["delivered"] += 1
        elif completed.status == "RETRY_SCHEDULED":
            counters["retry_scheduled"] += 1
        elif completed.status == "DEAD_LETTER":
            counters["dead_lettered"] += 1
        elif completed.status == "CANCELLED":
            counters["cancelled"] += 1

    return WebhookDispatchSummary(
        claimed=len(claimed),
        **counters,
    )

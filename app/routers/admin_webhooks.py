from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.audit_models import AuditContext
from app.dependencies import (
    get_evidence_store,
    get_webhook_transport,
    require_admin_access,
)
from app.evidence_store import EvidenceStore
from app.security import get_configured_webhook_master_secret
from app.services.projects import get_project_or_404
from app.services.webhooks import (
    create_webhook_subscription,
    disable_webhook_subscription,
    dispatch_pending_webhooks,
    get_webhook_delivery_detail_or_404,
    get_webhook_event_or_404,
    get_webhook_subscription_or_404,
    request_webhook_redelivery,
    rotate_webhook_subscription_secret,
)
from app.webhook_models import (
    WebhookDelivery,
    WebhookDeliveryDetail,
    WebhookDeliveryPage,
    WebhookDeliveryStatus,
    WebhookDispatchSummary,
    WebhookEvent,
    WebhookEventPage,
    WebhookEventType,
    WebhookSecretRotationResponse,
    WebhookSubscription,
    WebhookSubscriptionCreateRequest,
    WebhookSubscriptionPage,
    WebhookSubscriptionProvisioningResponse,
    WebhookSubscriptionStatus,
)
from app.webhooks import WebhookTransport


router = APIRouter()


@router.post(
    "/v1/admin/projects/{project_id}/webhook-subscriptions",
    response_model=WebhookSubscriptionProvisioningResponse,
    status_code=201,
)
def provision_webhook_subscription(
    project_id: UUID,
    request: WebhookSubscriptionCreateRequest,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    master_secret: str = Depends(
        get_configured_webhook_master_secret
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookSubscriptionProvisioningResponse:
    return create_webhook_subscription(
        project_id=project_id,
        request=request,
        master_secret=master_secret,
        store=store,
        audit_context=audit_context,
    )


@router.get(
    "/v1/admin/projects/{project_id}/webhook-subscriptions",
    response_model=WebhookSubscriptionPage,
    dependencies=[Depends(require_admin_access)],
)
def list_webhook_subscriptions(
    project_id: UUID,
    status: WebhookSubscriptionStatus | None = Query(
        default=None
    ),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookSubscriptionPage:
    get_project_or_404(project_id, store)

    return WebhookSubscriptionPage(
        items=store.list_webhook_subscriptions(
            project_id=project_id,
            status=status,
            limit=limit,
            offset=offset,
        ),
        total=store.count_webhook_subscriptions(
            project_id=project_id,
            status=status,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    (
        "/v1/admin/projects/{project_id}"
        "/webhook-subscriptions/{subscription_id}"
    ),
    response_model=WebhookSubscription,
    dependencies=[Depends(require_admin_access)],
)
def get_webhook_subscription(
    project_id: UUID,
    subscription_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookSubscription:
    get_project_or_404(project_id, store)

    return get_webhook_subscription_or_404(
        project_id=project_id,
        subscription_id=subscription_id,
        store=store,
    )


@router.delete(
    (
        "/v1/admin/projects/{project_id}"
        "/webhook-subscriptions/{subscription_id}"
    ),
    response_model=WebhookSubscription,
)
def remove_webhook_subscription(
    project_id: UUID,
    subscription_id: UUID,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookSubscription:
    return disable_webhook_subscription(
        project_id=project_id,
        subscription_id=subscription_id,
        store=store,
        audit_context=audit_context,
    )


@router.post(
    (
        "/v1/admin/projects/{project_id}"
        "/webhook-subscriptions/{subscription_id}"
        "/rotate-secret"
    ),
    response_model=WebhookSecretRotationResponse,
)
def rotate_webhook_secret(
    project_id: UUID,
    subscription_id: UUID,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    master_secret: str = Depends(
        get_configured_webhook_master_secret
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookSecretRotationResponse:
    return rotate_webhook_subscription_secret(
        project_id=project_id,
        subscription_id=subscription_id,
        master_secret=master_secret,
        store=store,
        audit_context=audit_context,
    )


@router.get(
    "/v1/admin/projects/{project_id}/webhook-events",
    response_model=WebhookEventPage,
    dependencies=[Depends(require_admin_access)],
)
def list_webhook_events(
    project_id: UUID,
    event_type: WebhookEventType | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookEventPage:
    get_project_or_404(project_id, store)

    return WebhookEventPage(
        items=store.list_webhook_events(
            project_id=project_id,
            event_type=event_type,
            limit=limit,
            offset=offset,
        ),
        total=store.count_webhook_events(
            project_id=project_id,
            event_type=event_type,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    (
        "/v1/admin/projects/{project_id}"
        "/webhook-events/{event_id}"
    ),
    response_model=WebhookEvent,
    dependencies=[Depends(require_admin_access)],
)
def get_webhook_event(
    project_id: UUID,
    event_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookEvent:
    get_project_or_404(project_id, store)

    return get_webhook_event_or_404(
        project_id=project_id,
        event_id=event_id,
        store=store,
    )


@router.get(
    "/v1/admin/projects/{project_id}/webhook-deliveries",
    response_model=WebhookDeliveryPage,
    dependencies=[Depends(require_admin_access)],
)
def list_webhook_deliveries(
    project_id: UUID,
    status: WebhookDeliveryStatus | None = Query(default=None),
    subscription_id: UUID | None = Query(default=None),
    event_id: UUID | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookDeliveryPage:
    get_project_or_404(project_id, store)

    return WebhookDeliveryPage(
        items=store.list_webhook_deliveries(
            project_id=project_id,
            status=status,
            subscription_id=subscription_id,
            event_id=event_id,
            limit=limit,
            offset=offset,
        ),
        total=store.count_webhook_deliveries(
            project_id=project_id,
            status=status,
            subscription_id=subscription_id,
            event_id=event_id,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    (
        "/v1/admin/projects/{project_id}"
        "/webhook-deliveries/{delivery_id}"
    ),
    response_model=WebhookDeliveryDetail,
    dependencies=[Depends(require_admin_access)],
)
def get_webhook_delivery(
    project_id: UUID,
    delivery_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookDeliveryDetail:
    get_project_or_404(project_id, store)

    return get_webhook_delivery_detail_or_404(
        project_id=project_id,
        delivery_id=delivery_id,
        store=store,
    )


@router.post(
    (
        "/v1/admin/projects/{project_id}"
        "/webhook-deliveries/{delivery_id}/redeliver"
    ),
    response_model=WebhookDelivery,
)
def redeliver_webhook(
    project_id: UUID,
    delivery_id: UUID,
    audit_context: AuditContext = Depends(
        require_admin_access
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> WebhookDelivery:
    return request_webhook_redelivery(
        project_id=project_id,
        delivery_id=delivery_id,
        store=store,
        audit_context=audit_context,
    )


@router.post(
    "/v1/admin/webhook-deliveries/dispatch",
    response_model=WebhookDispatchSummary,
    dependencies=[Depends(require_admin_access)],
)
def dispatch_webhook_deliveries(
    limit: int = Query(default=20, ge=1, le=100),
    master_secret: str = Depends(
        get_configured_webhook_master_secret
    ),
    store: EvidenceStore = Depends(get_evidence_store),
    transport: WebhookTransport = Depends(
        get_webhook_transport
    ),
) -> WebhookDispatchSummary:
    return dispatch_pending_webhooks(
        store=store,
        transport=transport,
        master_secret=master_secret,
        limit=limit,
    )

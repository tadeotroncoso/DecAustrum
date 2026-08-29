import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.webhook_models import (
    WebhookEvent,
    WebhookSubscription,
    WebhookSubscriptionCreateRequest,
)
from app.webhooks import (
    build_webhook_headers,
    canonical_webhook_payload,
    derive_webhook_signing_secret,
    sign_webhook_payload,
    verify_webhook_signature,
)


NOW = datetime(2026, 8, 29, 15, 0, tzinfo=timezone.utc)
MASTER_SECRET = "m" * 32


def build_event() -> WebhookEvent:
    return WebhookEvent(
        event_id=uuid4(),
        project_id=uuid4(),
        event_type="authorization.created",
        occurred_at=NOW,
        resource_type="AUTHORIZATION_DECISION",
        resource_id=str(uuid4()),
        data={"message": "Autorización creada", "value": 1},
    )


def test_subscription_request_defaults_to_all_events():
    request = WebhookSubscriptionCreateRequest(
        url="  https://hooks.example.com/regtrace  "
    )

    assert request.url == "https://hooks.example.com/regtrace"
    assert request.event_types == ["*"]


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/regtrace",
        "https://localhost/regtrace",
        "https://127.0.0.1/regtrace",
        "https://10.0.0.1/regtrace",
        "https://user:password@hooks.example.com/regtrace",
        "https://hooks.example.com/regtrace#secret",
    ],
)
def test_subscription_rejects_unsafe_url(url):
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateRequest(url=url)


@pytest.mark.parametrize(
    "event_types",
    [
        ["authorization.created", "authorization.created"],
        ["*", "approval.resolved"],
    ],
)
def test_subscription_rejects_ambiguous_event_selectors(
    event_types,
):
    with pytest.raises(ValidationError):
        WebhookSubscriptionCreateRequest(
            url="https://hooks.example.com/regtrace",
            event_types=event_types,
        )


def test_disabled_subscription_requires_disabled_at():
    with pytest.raises(
        ValidationError,
        match="requires disabled_at",
    ):
        WebhookSubscription(
            subscription_id=uuid4(),
            project_id=uuid4(),
            url="https://hooks.example.com/regtrace",
            event_types=["*"],
            status="DISABLED",
            created_at=NOW,
            updated_at=NOW,
        )


def test_webhook_event_requires_timezone_aware_timestamp():
    with pytest.raises(
        ValidationError,
        match="occurred_at must include a timezone",
    ):
        WebhookEvent(
            event_id=uuid4(),
            project_id=uuid4(),
            event_type="authorization.created",
            occurred_at=datetime(2026, 8, 29, 15, 0),
            resource_type="AUTHORIZATION_DECISION",
            resource_id=str(uuid4()),
            data={},
        )


def test_webhook_secret_is_derived_and_rotatable():
    subscription_id = uuid4()

    first = derive_webhook_signing_secret(
        MASTER_SECRET,
        subscription_id,
        1,
    )
    repeated = derive_webhook_signing_secret(
        MASTER_SECRET,
        subscription_id,
        1,
    )
    rotated = derive_webhook_signing_secret(
        MASTER_SECRET,
        subscription_id,
        2,
    )

    assert first.startswith("whsec_")
    assert first == repeated
    assert rotated != first
    assert MASTER_SECRET not in first


def test_canonical_payload_and_signature_are_verifiable():
    event = build_event()
    payload = canonical_webhook_payload(event)
    subscription_id = uuid4()
    signing_secret = derive_webhook_signing_secret(
        MASTER_SECRET,
        subscription_id,
        1,
    )
    timestamp = int(NOW.timestamp())
    signature = sign_webhook_payload(
        payload,
        timestamp,
        signing_secret,
    )

    decoded = json.loads(payload)

    assert decoded["event_type"] == "authorization.created"
    assert decoded["data"]["message"] == "Autorización creada"
    assert verify_webhook_signature(
        payload=payload,
        timestamp=timestamp,
        signature=signature,
        signing_secret=signing_secret,
        now=NOW,
    )
    assert not verify_webhook_signature(
        payload=payload + b" ",
        timestamp=timestamp,
        signature=signature,
        signing_secret=signing_secret,
        now=NOW,
    )
    assert not verify_webhook_signature(
        payload=payload,
        timestamp=timestamp,
        signature=signature,
        signing_secret=signing_secret,
        now=NOW + timedelta(minutes=6),
    )


def test_webhook_headers_identify_and_sign_delivery():
    event = build_event()
    payload = canonical_webhook_payload(event)
    delivery_id = uuid4()
    signing_secret = derive_webhook_signing_secret(
        MASTER_SECRET,
        uuid4(),
        1,
    )
    headers = build_webhook_headers(
        event=event,
        delivery_id=delivery_id,
        payload=payload,
        timestamp=int(NOW.timestamp()),
        signing_secret=signing_secret,
    )

    assert headers["X-RegTrace-Delivery-Id"] == str(delivery_id)
    assert headers["X-RegTrace-Event-Id"] == str(event.event_id)
    assert headers["X-RegTrace-Event-Type"] == event.event_type
    assert verify_webhook_signature(
        payload=payload,
        timestamp=headers["X-RegTrace-Timestamp"],
        signature=headers["X-RegTrace-Signature"],
        signing_secret=signing_secret,
        now=NOW,
    )

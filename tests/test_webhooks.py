import json
import socket
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

import app.webhooks as webhook_module
from app.webhook_models import (
    WebhookEvent,
    WebhookSubscription,
    WebhookSubscriptionCreateRequest,
)
from app.webhooks import (
    build_webhook_headers,
    canonical_webhook_payload,
    derive_webhook_signing_secret,
    ensure_public_webhook_destination,
    sign_webhook_payload,
    UrllibWebhookTransport,
    WebhookTransportError,
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


def address_info(address: str, port: int = 443):
    if ":" in address:
        return (
            socket.AF_INET6,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, port, 0, 0),
        )

    return (
        socket.AF_INET,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, port),
    )


def test_webhook_destination_accepts_only_public_dns_results(
    monkeypatch,
):
    monkeypatch.setattr(
        webhook_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            address_info("8.8.8.8"),
            address_info("2606:4700:4700::1111"),
        ],
    )

    ensure_public_webhook_destination(
        "https://hooks.example.com/regtrace"
    )


@pytest.mark.parametrize(
    "addresses",
    [
        ["127.0.0.1"],
        ["10.0.0.1"],
        ["8.8.8.8", "192.168.1.10"],
        ["2001:db8::1"],
    ],
)
def test_webhook_destination_rejects_any_non_public_dns_result(
    monkeypatch,
    addresses,
):
    monkeypatch.setattr(
        webhook_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            address_info(address)
            for address in addresses
        ],
    )

    with pytest.raises(
        WebhookTransportError,
        match="private or reserved",
    ):
        ensure_public_webhook_destination(
            "https://hooks.example.com/regtrace"
        )


def test_webhook_destination_hides_dns_resolution_errors(monkeypatch):
    def fail_resolution(*_args, **_kwargs):
        raise OSError("sensitive resolver detail")

    monkeypatch.setattr(
        webhook_module.socket,
        "getaddrinfo",
        fail_resolution,
    )

    with pytest.raises(
        WebhookTransportError,
        match="could not be resolved",
    ) as error:
        ensure_public_webhook_destination(
            "https://hooks.example.com/regtrace"
        )

    assert "sensitive resolver detail" not in str(error.value)


def test_real_transport_pins_validated_ip_preserves_tls_host_and_redirect(
    monkeypatch,
):
    connected_addresses = []
    tls_hostnames = []
    requests = []

    class FakeSocket:
        def settimeout(self, timeout):
            assert timeout == 2.5

        def connect(self, socket_address):
            connected_addresses.append(socket_address)

        def close(self):
            pass

    class FakeTlsContext:
        def wrap_socket(self, raw_socket, *, server_hostname):
            tls_hostnames.append(server_hostname)
            return raw_socket

    class FakeHttpsConnection:
        def __init__(self, *, host, port, timeout, context):
            assert host == "hooks.example.com"
            assert port == 443
            assert timeout == 2.5
            assert isinstance(context, FakeTlsContext)
            self.sock = None

        def request(self, *, method, url, body, headers):
            requests.append((method, url, body, headers))

        def getresponse(self):
            return SimpleNamespace(status=302)

        def close(self):
            pass

    monkeypatch.setattr(
        webhook_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [address_info("8.8.8.8")],
    )
    monkeypatch.setattr(
        webhook_module.socket,
        "socket",
        lambda *_args: FakeSocket(),
    )
    monkeypatch.setattr(
        webhook_module.ssl,
        "create_default_context",
        FakeTlsContext,
    )
    monkeypatch.setattr(
        webhook_module.http.client,
        "HTTPSConnection",
        FakeHttpsConnection,
    )

    response = UrllibWebhookTransport().send(
        url="https://hooks.example.com/regtrace?source=test",
        body=b"{}",
        headers={"Content-Type": "application/json"},
        timeout_seconds=2.5,
    )

    assert response.status_code == 302
    assert connected_addresses == [("8.8.8.8", 443)]
    assert tls_hostnames == ["hooks.example.com"]
    assert requests == [
        (
            "POST",
            "/regtrace?source=test",
            b"{}",
            {"Content-Type": "application/json"},
        )
    ]


def test_real_transport_rejects_private_resolution_before_connecting(
    monkeypatch,
):
    monkeypatch.setattr(
        webhook_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [address_info("127.0.0.1")],
    )

    def unexpected_socket(*_args, **_kwargs):
        raise AssertionError("A private destination must not be opened.")

    monkeypatch.setattr(
        webhook_module.socket,
        "socket",
        unexpected_socket,
    )

    with pytest.raises(
        WebhookTransportError,
        match="private or reserved",
    ):
        UrllibWebhookTransport().send(
            url="https://hooks.example.com/regtrace",
            body=b"{}",
            headers={},
            timeout_seconds=2.5,
        )

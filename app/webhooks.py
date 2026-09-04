import base64
import hashlib
import hmac
import http.client
import json
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel

from app.audit_models import AdministrativeAuditEvent, AuditAction
from app.webhook_models import (
    WebhookEvent,
    WebhookEventType,
    WebhookResourceType,
    validate_webhook_url,
)

AUDIT_WEBHOOK_EVENT_TYPES: dict[AuditAction, WebhookEventType] = {
    "PROJECT_CREATED": "project.created",
    "PROJECT_STATUS_CHANGED": "project.status_changed",
    "API_KEY_CREATED": "api_key.created",
    "API_KEY_REVOKED": "api_key.revoked",
    "POLICY_CREATED": "policy.created",
    "POLICY_UPDATED": "policy.updated",
    "POLICY_DISABLED": "policy.disabled",
    "POLICY_ROLLED_BACK": "policy.rolled_back",
    "APPROVAL_RESOLVED": "approval.resolved",
    "APPROVAL_EXPIRED": "approval.expired",
    "EXECUTION_GRANT_ISSUED": "execution_grant.issued",
    "EXECUTION_GRANT_CONSUMED": "execution_grant.consumed",
    "EXECUTION_GRANT_EXPIRED": "execution_grant.expired",
    "WEBHOOK_SUBSCRIPTION_CREATED": (
        "webhook.subscription.created"
    ),
    "WEBHOOK_SUBSCRIPTION_DISABLED": (
        "webhook.subscription.disabled"
    ),
    "WEBHOOK_SECRET_ROTATED": (  # nosec B105
        "webhook.subscription.secret_rotated"
    ),
    "WEBHOOK_REDELIVERY_REQUESTED": (
        "webhook.delivery.redelivery_requested"
    ),
}

AUDIT_WEBHOOK_RESOURCE_TYPES: dict[str, WebhookResourceType] = {
    "PROJECT": "PROJECT",
    "API_KEY": "API_KEY",
    "POLICY": "POLICY",
    "APPROVAL": "APPROVAL",
    "EXECUTION_GRANT": "EXECUTION_GRANT",
    "WEBHOOK_SUBSCRIPTION": "WEBHOOK_SUBSCRIPTION",
    "WEBHOOK_DELIVERY": "WEBHOOK_DELIVERY",
}


def _json_data(
    value: BaseModel | dict[str, Any],
) -> dict[str, Any]:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")

    return value


def build_webhook_event(
    *,
    project_id: UUID,
    event_type: WebhookEventType,
    occurred_at: datetime,
    resource_type: WebhookResourceType,
    resource_id: str,
    data: BaseModel | dict[str, Any],
) -> WebhookEvent:
    return WebhookEvent(
        event_id=uuid4(),
        project_id=project_id,
        event_type=event_type,
        occurred_at=occurred_at,
        resource_type=resource_type,
        resource_id=resource_id,
        data=_json_data(data),
    )


def build_webhook_event_from_audit(
    event: AdministrativeAuditEvent,
) -> WebhookEvent:
    return build_webhook_event(
        project_id=event.project_id,
        event_type=AUDIT_WEBHOOK_EVENT_TYPES[event.action],
        occurred_at=event.occurred_at,
        resource_type=AUDIT_WEBHOOK_RESOURCE_TYPES[
            event.resource_type
        ],
        resource_id=event.resource_id,
        data={
            "audit_event": event.model_dump(mode="json"),
        },
    )


def canonical_webhook_payload(event: WebhookEvent) -> bytes:
    return json.dumps(
        event.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def derive_webhook_signing_secret(
    master_secret: str,
    subscription_id: UUID,
    secret_version: int,
) -> str:
    if len(master_secret.encode("utf-8")) < 32:
        raise ValueError(
            "Webhook master secret must contain at least 32 bytes."
        )

    if secret_version < 1:
        raise ValueError("Webhook secret version must be positive.")

    message = (
        "decaustrum-webhook:"
        f"{subscription_id}:{secret_version}"
    ).encode("utf-8")
    digest = hmac.new(
        master_secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii")

    return "whsec_" + encoded.rstrip("=")


def sign_webhook_payload(
    payload: bytes,
    timestamp: int,
    signing_secret: str,
) -> str:
    signed_payload = (
        str(timestamp).encode("ascii")
        + b"."
        + payload
    )
    digest = hmac.new(
        signing_secret.encode("utf-8"),
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return f"v1={digest}"


def verify_webhook_signature(
    *,
    payload: bytes,
    timestamp: str | int,
    signature: str,
    signing_secret: str,
    now: datetime | None = None,
    tolerance_seconds: int = 300,
) -> bool:
    try:
        timestamp_value = int(timestamp)
    except (TypeError, ValueError):
        return False

    reference_time = now or datetime.now(timezone.utc)

    if reference_time.tzinfo is None:
        raise ValueError("Webhook verification time needs a timezone.")

    if tolerance_seconds < 0:
        raise ValueError("Webhook tolerance cannot be negative.")

    if abs(reference_time.timestamp() - timestamp_value) > (
        tolerance_seconds
    ):
        return False

    expected = sign_webhook_payload(
        payload=payload,
        timestamp=timestamp_value,
        signing_secret=signing_secret,
    )

    return hmac.compare_digest(expected, signature)


def build_webhook_headers(
    *,
    event: WebhookEvent,
    delivery_id: UUID,
    payload: bytes,
    timestamp: int,
    signing_secret: str,
) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "User-Agent": "DecAustrum-Webhooks/0.1",
        "X-DecAustrum-Delivery-Id": str(delivery_id),
        "X-DecAustrum-Event-Id": str(event.event_id),
        "X-DecAustrum-Event-Type": event.event_type,
        "X-DecAustrum-Timestamp": str(timestamp),
        "X-DecAustrum-Signature": sign_webhook_payload(
            payload=payload,
            timestamp=timestamp,
            signing_secret=signing_secret,
        ),
    }


@dataclass(frozen=True)
class WebhookHttpResponse:
    status_code: int


class WebhookTransportError(Exception):
    pass


class WebhookTransport(Protocol):
    def send(
        self,
        *,
        url: str,
        body: bytes,
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> WebhookHttpResponse:
        ...


@dataclass(frozen=True)
class _ResolvedWebhookAddress:
    family: int
    socket_type: int
    protocol: int
    socket_address: tuple[Any, ...]


def _resolve_public_webhook_destination(
    url: str,
) -> tuple[str, int, tuple[_ResolvedWebhookAddress, ...]]:
    try:
        validate_webhook_url(url)
    except ValueError as exc:
        raise WebhookTransportError(
            "Webhook destination is not a safe HTTPS URL."
        ) from exc

    parsed = urlsplit(url)
    hostname = parsed.hostname

    if hostname is None:
        raise WebhookTransportError(
            "Webhook destination has no host."
        )

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise WebhookTransportError(
            "Webhook destination has an invalid port."
        ) from exc

    try:
        address_info = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except (OSError, ValueError) as exc:
        raise WebhookTransportError(
            "Webhook destination could not be resolved."
        ) from exc

    resolved_addresses = []
    addresses = set()

    for (
        family,
        socket_type,
        protocol,
        _canonical_name,
        socket_address,
    ) in address_info:
        try:
            address = ip_address(socket_address[0])
        except ValueError as exc:
            raise WebhookTransportError(
                "Webhook destination returned an invalid address."
            ) from exc

        addresses.add(address)
        resolved_addresses.append(
            _ResolvedWebhookAddress(
                family=family,
                socket_type=socket_type,
                protocol=protocol,
                socket_address=socket_address,
            )
        )

    if not addresses or any(
        not address.is_global
        for address in addresses
    ):
        raise WebhookTransportError(
            "Webhook destination resolved to a private or "
            "reserved address."
        )

    return hostname, port, tuple(resolved_addresses)


def ensure_public_webhook_destination(url: str) -> None:
    _resolve_public_webhook_destination(url)


def _open_pinned_https_connection(
    *,
    hostname: str,
    port: int,
    address: _ResolvedWebhookAddress,
    timeout_seconds: float,
    tls_context: ssl.SSLContext,
) -> http.client.HTTPSConnection:
    raw_socket = socket.socket(
        address.family,
        address.socket_type,
        address.protocol,
    )

    try:
        raw_socket.settimeout(timeout_seconds)
        raw_socket.connect(address.socket_address)
        tls_socket = tls_context.wrap_socket(
            raw_socket,
            server_hostname=hostname,
        )
    except Exception:
        raw_socket.close()
        raise

    connection = http.client.HTTPSConnection(
        host=hostname,
        port=port,
        timeout=timeout_seconds,
        context=tls_context,
    )
    connection.sock = tls_socket

    return connection


class UrllibWebhookTransport:
    def send(
        self,
        *,
        url: str,
        body: bytes,
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> WebhookHttpResponse:
        hostname, port, addresses = (
            _resolve_public_webhook_destination(url)
        )
        parsed = urlsplit(url)
        request_target = parsed.path or "/"

        if parsed.query:
            request_target += "?" + parsed.query

        tls_context = ssl.create_default_context()
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        last_error: BaseException | None = None

        for address in addresses:
            connection = None

            try:
                connection = _open_pinned_https_connection(
                    hostname=hostname,
                    port=port,
                    address=address,
                    timeout_seconds=timeout_seconds,
                    tls_context=tls_context,
                )
                connection.request(
                    method="POST",
                    url=request_target,
                    body=body,
                    headers=headers,
                )
                response = connection.getresponse()

                return WebhookHttpResponse(
                    status_code=response.status
                )
            except (
                http.client.HTTPException,
                OSError,
                TimeoutError,
            ) as exc:
                last_error = exc
            finally:
                if connection is not None:
                    connection.close()

        raise WebhookTransportError(
            "Webhook request failed before receiving "
            "an HTTP response."
        ) from last_error

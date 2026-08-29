import base64
import hashlib
import hmac
import json
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)
from uuid import UUID, uuid4

from pydantic import BaseModel

from app.audit_models import AdministrativeAuditEvent, AuditAction
from app.webhook_models import (
    WebhookEvent,
    WebhookEventType,
    WebhookResourceType,
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
    "WEBHOOK_SECRET_ROTATED": (
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
        "regtrace-webhook:"
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
        "User-Agent": "RegTrace-Webhooks/0.1",
        "X-RegTrace-Delivery-Id": str(delivery_id),
        "X-RegTrace-Event-Id": str(event.event_id),
        "X-RegTrace-Event-Type": event.event_type,
        "X-RegTrace-Timestamp": str(timestamp),
        "X-RegTrace-Signature": sign_webhook_payload(
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


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def ensure_public_webhook_destination(url: str) -> None:
    parsed = urlsplit(url)
    hostname = parsed.hostname

    if hostname is None:
        raise WebhookTransportError(
            "Webhook destination has no host."
        )

    try:
        addresses = {
            ip_address(sockaddr[0])
            for *_prefix, sockaddr in socket.getaddrinfo(
                hostname,
                parsed.port or 443,
                type=socket.SOCK_STREAM,
            )
        }
    except (OSError, ValueError) as exc:
        raise WebhookTransportError(
            "Webhook destination could not be resolved."
        ) from exc

    if not addresses or any(
        not address.is_global
        for address in addresses
    ):
        raise WebhookTransportError(
            "Webhook destination resolved to a private or "
            "reserved address."
        )


class UrllibWebhookTransport:
    def send(
        self,
        *,
        url: str,
        body: bytes,
        headers: dict[str, str],
        timeout_seconds: float,
    ) -> WebhookHttpResponse:
        ensure_public_webhook_destination(url)
        request = Request(
            url=url,
            data=body,
            headers=headers,
            method="POST",
        )
        opener = build_opener(_NoRedirectHandler())

        try:
            with opener.open(
                request,
                timeout=timeout_seconds,
            ) as response:
                return WebhookHttpResponse(
                    status_code=response.status
                )
        except HTTPError as exc:
            return WebhookHttpResponse(status_code=exc.code)
        except (URLError, OSError, TimeoutError) as exc:
            raise WebhookTransportError(
                "Webhook request failed before receiving "
                "an HTTP response."
            ) from exc

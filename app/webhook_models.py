from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


WebhookEventType = Literal[
    "authorization.created",
    "approval.requested",
    "approval.resolved",
    "approval.expired",
    "execution_grant.issued",
    "execution_grant.consumed",
    "execution_grant.expired",
    "project.created",
    "project.status_changed",
    "api_key.created",
    "api_key.revoked",
    "policy.created",
    "policy.updated",
    "policy.disabled",
    "policy.rolled_back",
    "webhook.subscription.created",
    "webhook.subscription.disabled",
    "webhook.subscription.secret_rotated",
    "webhook.delivery.redelivery_requested",
]

WEBHOOK_EVENT_TYPES: tuple[WebhookEventType, ...] = (
    "authorization.created",
    "approval.requested",
    "approval.resolved",
    "approval.expired",
    "execution_grant.issued",
    "execution_grant.consumed",
    "execution_grant.expired",
    "project.created",
    "project.status_changed",
    "api_key.created",
    "api_key.revoked",
    "policy.created",
    "policy.updated",
    "policy.disabled",
    "policy.rolled_back",
    "webhook.subscription.created",
    "webhook.subscription.disabled",
    "webhook.subscription.secret_rotated",
    "webhook.delivery.redelivery_requested",
)

WebhookEventSelector = Literal[
    "*",
    "authorization.created",
    "approval.requested",
    "approval.resolved",
    "approval.expired",
    "execution_grant.issued",
    "execution_grant.consumed",
    "execution_grant.expired",
    "project.created",
    "project.status_changed",
    "api_key.created",
    "api_key.revoked",
    "policy.created",
    "policy.updated",
    "policy.disabled",
    "policy.rolled_back",
    "webhook.subscription.created",
    "webhook.subscription.disabled",
    "webhook.subscription.secret_rotated",
    "webhook.delivery.redelivery_requested",
]

WebhookSubscriptionStatus = Literal[
    "ACTIVE",
    "DISABLED",
]

WebhookDeliveryStatus = Literal[
    "PENDING",
    "PROCESSING",
    "RETRY_SCHEDULED",
    "DELIVERED",
    "DEAD_LETTER",
    "CANCELLED",
]

WebhookDeliveryOutcome = Literal[
    "SUCCESS",
    "HTTP_ERROR",
    "NETWORK_ERROR",
]

WebhookResourceType = Literal[
    "AUTHORIZATION_DECISION",
    "APPROVAL",
    "EXECUTION_GRANT",
    "PROJECT",
    "API_KEY",
    "POLICY",
    "WEBHOOK_SUBSCRIPTION",
    "WEBHOOK_DELIVERY",
]


def validate_webhook_url(value: str) -> str:
    parsed = urlsplit(value)

    if parsed.scheme.lower() != "https":
        raise ValueError("Webhook URL must use HTTPS.")

    if parsed.hostname is None:
        raise ValueError("Webhook URL must include a host.")

    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Webhook URL cannot include credentials.")

    if parsed.fragment:
        raise ValueError("Webhook URL cannot include a fragment.")

    hostname = parsed.hostname.lower()

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("Webhook URL cannot target localhost.")

    try:
        literal_address = ip_address(hostname)
    except ValueError:
        literal_address = None

    if literal_address is not None and not literal_address.is_global:
        raise ValueError(
            "Webhook URL cannot target a private or reserved address."
        )

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Webhook URL contains an invalid port.") from exc

    return value


WebhookUrl = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=2048,
    ),
    AfterValidator(validate_webhook_url),
]

WebhookSigningSecret = Annotated[
    str,
    StringConstraints(
        pattern=r"^whsec_[A-Za-z0-9_-]{43}$",
    ),
]


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone.")

    return value.astimezone(timezone.utc)


def _normalize_event_selectors(
    values: list[WebhookEventSelector],
) -> list[WebhookEventSelector]:
    if len(values) != len(set(values)):
        raise ValueError("Webhook event types must be unique.")

    if "*" in values and len(values) != 1:
        raise ValueError(
            "Wildcard event selector '*' must be used alone."
        )

    return values


class WebhookSubscriptionCreateRequest(BaseModel):
    url: WebhookUrl
    event_types: list[WebhookEventSelector] = Field(
        default_factory=lambda: ["*"],
        min_length=1,
        max_length=len(WEBHOOK_EVENT_TYPES),
    )

    @field_validator("event_types")
    @classmethod
    def validate_event_types(
        cls,
        values: list[WebhookEventSelector],
    ) -> list[WebhookEventSelector]:
        return _normalize_event_selectors(values)


class WebhookSubscription(BaseModel):
    subscription_id: UUID
    project_id: UUID
    url: WebhookUrl
    event_types: list[WebhookEventSelector] = Field(
        min_length=1,
        max_length=len(WEBHOOK_EVENT_TYPES),
    )
    status: WebhookSubscriptionStatus = "ACTIVE"
    secret_version: int = Field(default=1, ge=1)
    created_at: datetime
    updated_at: datetime
    disabled_at: datetime | None = None

    @field_validator("event_types")
    @classmethod
    def validate_event_types(
        cls,
        values: list[WebhookEventSelector],
    ) -> list[WebhookEventSelector]:
        return _normalize_event_selectors(values)

    @field_validator("created_at", "updated_at")
    @classmethod
    def require_timestamp_timezone(
        cls,
        value: datetime,
        info,
    ) -> datetime:
        return _utc(value, info.field_name)

    @field_validator("disabled_at")
    @classmethod
    def require_disabled_timezone(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is None:
            return None

        return _utc(value, "disabled_at")

    @model_validator(mode="after")
    def validate_status_timestamps(self):
        if self.status == "ACTIVE" and self.disabled_at is not None:
            raise ValueError(
                "Active webhook subscription cannot have disabled_at."
            )

        if self.status == "DISABLED" and self.disabled_at is None:
            raise ValueError(
                "Disabled webhook subscription requires disabled_at."
            )

        return self


class WebhookSubscriptionProvisioningResponse(BaseModel):
    subscription: WebhookSubscription
    signing_secret: WebhookSigningSecret


class WebhookSecretRotationResponse(BaseModel):
    subscription: WebhookSubscription
    signing_secret: WebhookSigningSecret


class WebhookSubscriptionPage(BaseModel):
    items: list[WebhookSubscription]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class WebhookEvent(BaseModel):
    event_id: UUID
    project_id: UUID
    event_type: WebhookEventType
    occurred_at: datetime
    resource_type: WebhookResourceType
    resource_id: str = Field(min_length=1, max_length=200)
    data: dict[str, Any]
    schema_version: Literal[1] = 1

    @field_validator("occurred_at")
    @classmethod
    def require_occurred_at_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        return _utc(value, "occurred_at")


class WebhookEventPage(BaseModel):
    items: list[WebhookEvent]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class WebhookDelivery(BaseModel):
    delivery_id: UUID
    event_id: UUID
    subscription_id: UUID
    project_id: UUID
    status: WebhookDeliveryStatus
    attempt_count: int = Field(default=0, ge=0)
    failure_count: int = Field(default=0, ge=0)
    redelivery_count: int = Field(default=0, ge=0)
    next_attempt_at: datetime | None = None
    lease_expires_at: datetime | None = None
    delivered_at: datetime | None = None
    last_attempt_at: datetime | None = None
    last_status_code: int | None = Field(default=None, ge=100, le=599)
    last_error: str | None = Field(default=None, max_length=1000)
    created_at: datetime
    updated_at: datetime

    @field_validator(
        "next_attempt_at",
        "lease_expires_at",
        "delivered_at",
        "last_attempt_at",
        "created_at",
        "updated_at",
    )
    @classmethod
    def require_delivery_timestamp_timezone(
        cls,
        value: datetime | None,
        info,
    ) -> datetime | None:
        if value is None:
            return None

        return _utc(value, info.field_name)


class WebhookDeliveryPage(BaseModel):
    items: list[WebhookDelivery]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class WebhookDeliveryAttempt(BaseModel):
    attempt_id: UUID
    delivery_id: UUID
    attempt_number: int = Field(ge=1)
    attempted_at: datetime
    completed_at: datetime
    outcome: WebhookDeliveryOutcome
    status_code: int | None = Field(default=None, ge=100, le=599)
    error: str | None = Field(default=None, max_length=1000)

    @field_validator("attempted_at", "completed_at")
    @classmethod
    def require_attempt_timestamp_timezone(
        cls,
        value: datetime,
        info,
    ) -> datetime:
        return _utc(value, info.field_name)


class WebhookDeliveryDetail(BaseModel):
    delivery: WebhookDelivery
    event: WebhookEvent
    subscription: WebhookSubscription
    attempts: list[WebhookDeliveryAttempt]


class WebhookDispatchSummary(BaseModel):
    claimed: int = Field(ge=0)
    delivered: int = Field(ge=0)
    retry_scheduled: int = Field(ge=0)
    dead_lettered: int = Field(ge=0)
    cancelled: int = Field(ge=0)

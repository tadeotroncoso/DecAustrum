from pathlib import Path
from typing import Annotated

from fastapi import Depends, Header, Request

from app.audit_models import (
    AuditActorIdentifier,
    AuditContext,
    AuditReason,
)
from app.evidence_store import EvidenceStore
from app.observability import MetricsRegistry
from app.project_models import Project
from app.runtime_config import RuntimeSettings
from app.security import (
    admin_api_key_header,
    api_key_header,
    authenticate_admin,
    authenticate_project,
    get_configured_admin_api_key,
    get_configured_execution_grant_secret,
)
from app.webhooks import (
    UrllibWebhookTransport,
    WebhookTransport,
)

DATABASE_PATH = Path("data/decaustrum.db")
evidence_store = EvidenceStore(DATABASE_PATH)
webhook_transport = UrllibWebhookTransport()


def get_evidence_store() -> EvidenceStore:
    return evidence_store


def get_webhook_transport() -> WebhookTransport:
    return webhook_transport


def get_metrics_registry(request: Request) -> MetricsRegistry:
    return request.app.state.metrics_registry


def get_runtime_settings(request: Request) -> RuntimeSettings:
    return request.app.state.runtime_settings


def get_execution_grant_secret() -> str:
    return get_configured_execution_grant_secret()


def get_authenticated_project(
    request: Request,
    provided_api_key: Annotated[
        str | None,
        Depends(api_key_header),
    ],
    store: EvidenceStore = Depends(get_evidence_store),
) -> Project:
    project = authenticate_project(
        provided_api_key=provided_api_key,
        store=store,
    )
    request.state.principal_type = "project"
    return project


def require_admin_access(
    request: Request,
    provided_api_key: Annotated[
        str | None,
        Depends(admin_api_key_header),
    ],
    admin_actor: Annotated[
        AuditActorIdentifier | None,
        Header(alias="X-Admin-Actor"),
    ] = None,
    audit_reason: Annotated[
        AuditReason | None,
        Header(alias="X-Audit-Reason"),
    ] = None,
) -> AuditContext:
    authenticate_admin(
        provided_api_key=provided_api_key,
        configured_api_key=(
            get_configured_admin_api_key()
        ),
    )
    request.state.principal_type = "admin"

    return AuditContext(
        actor_type="ADMIN",
        actor_id=admin_actor or "admin-api-key",
        reason=audit_reason,
    )

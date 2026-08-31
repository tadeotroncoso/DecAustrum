import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.audit import SYSTEM_BOOTSTRAP_AUDIT_CONTEXT
from app.bootstrap import bootstrap_default_project
from app.dependencies import (
    DATABASE_PATH,
    evidence_store,
    get_authenticated_project,
    get_evidence_store,
    require_admin_access,
)
from app.http_middleware import SecurityObservabilityMiddleware
from app.observability import (
    MetricsRegistry,
    DECAUSTRUM_VERSION,
    configure_json_logging,
)
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID
from app.rate_limit import FixedWindowRateLimiter
from app.routers import (
    admin_audit,
    admin_policies,
    admin_projects,
    admin_webhooks,
    approvals,
    authorization,
    decisions,
    evidence,
    execution_grants,
    health,
    integrity,
    observability,
    policies,
)
from app.runtime_config import RuntimeSettings
from app.security import (
    ADMIN_API_KEY_ENVIRONMENT_VARIABLE,
    EXECUTION_GRANT_SECRET_ENVIRONMENT_VARIABLE,
    get_configured_api_key,
)


LOGGER = logging.getLogger("decaustrum.lifecycle")

API_DESCRIPTION = (
    "Project-scoped authorization, human approval, one-time execution "
    "grants, and verifiable decision evidence for automated systems."
)

OPENAPI_TAGS = [
    {
        "name": "Health",
        "description": "Liveness, readiness, and compatibility health checks.",
    },
    {
        "name": "Authorization",
        "description": (
            "Evaluate an action against the authenticated "
            "project's active policies."
        ),
    },
    {
        "name": "Policies",
        "description": "Read the active policy set for the authenticated project.",
    },
    {
        "name": "Decisions",
        "description": "Search and retrieve persisted authorization decisions.",
    },
    {
        "name": "Evidence",
        "description": "Export filtered evidence and build offline-verifiable bundles.",
    },
    {
        "name": "Integrity",
        "description": "Inspect and verify the per-project decision hash chain.",
    },
    {
        "name": "Approvals",
        "description": "Review pending decisions and issue one-time execution grants.",
    },
    {
        "name": "Execution grants",
        "description": (
            "Consume a grant bound to an approved agent, "
            "action, and context."
        ),
    },
    {
        "name": "Administration: projects",
        "description": (
            "Provision projects and manage project API keys "
            "and lifecycle state."
        ),
    },
    {
        "name": "Administration: policies",
        "description": (
            "Configure project policies and inspect immutable "
            "version history."
        ),
    },
    {
        "name": "Administration: audit",
        "description": "Search the append-only administrative audit trail.",
    },
    {
        "name": "Administration: webhooks",
        "description": (
            "Manage signed webhook subscriptions, events, "
            "and delivery attempts."
        ),
    },
]


def _sanitized_validation_errors(
    exception: RequestValidationError,
) -> list[dict[str, Any]]:
    return [
        {
            "type": error["type"],
            "loc": list(error["loc"]),
            "msg": error["msg"],
        }
        for error in exception.errors()[:50]
    ]


@asynccontextmanager
async def lifespan(application: FastAPI):
    settings: RuntimeSettings = application.state.runtime_settings
    metrics: MetricsRegistry = application.state.metrics_registry
    configure_json_logging(settings.log_level)
    metrics.set_ready(False)
    LOGGER.info("application_starting")

    try:
        api_key = get_configured_api_key()
        settings.validate_secrets(
            project_api_key=api_key,
            admin_api_key=os.getenv(
                ADMIN_API_KEY_ENVIRONMENT_VARIABLE
            ),
            execution_grant_secret=os.getenv(
                EXECUTION_GRANT_SECRET_ENVIRONMENT_VARIABLE
            ),
        )
        policy_templates = load_policies(POLICIES_DIRECTORY)
        evidence_store.initialize()

        bootstrap_default_project(
            store=evidence_store,
            api_key=api_key,
        )

        evidence_store.seed_project_policies(
            project_id=DEFAULT_PROJECT_ID,
            policies=policy_templates,
            seeded_at=datetime.now(timezone.utc),
            audit_context=SYSTEM_BOOTSTRAP_AUDIT_CONTEXT,
        )

        metrics.set_ready(True)
        LOGGER.info("application_ready")
        yield
    except Exception:
        LOGGER.exception("application_failed")
        raise
    finally:
        metrics.set_ready(False)
        LOGGER.info("application_stopped")


def create_app(
    settings: RuntimeSettings | None = None,
) -> FastAPI:
    runtime_settings = settings or RuntimeSettings.from_environment()
    metrics = MetricsRegistry()
    rate_limiter = FixedWindowRateLimiter()
    docs_url = "/docs" if runtime_settings.expose_docs else None
    openapi_url = (
        "/openapi.json"
        if runtime_settings.expose_docs
        else None
    )

    application = FastAPI(
        title="DecAustrum API",
        description=API_DESCRIPTION,
        version=DECAUSTRUM_VERSION,
        openapi_tags=OPENAPI_TAGS,
        license_info={
            "name": "DecAustrum Portfolio Evaluation License 1.0",
            "identifier": (
                "LicenseRef-DecAustrum-Portfolio-Evaluation-1.0"
            ),
        },
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=(
            "/redoc"
            if runtime_settings.expose_docs
            else None
        ),
        openapi_url=openapi_url,
    )
    application.state.runtime_settings = runtime_settings
    application.state.metrics_registry = metrics
    application.state.rate_limiter = rate_limiter
    application.add_middleware(
        SecurityObservabilityMiddleware,
        settings=runtime_settings,
        metrics=metrics,
        rate_limiter=rate_limiter,
    )

    @application.exception_handler(RequestValidationError)
    async def sanitized_validation_exception_handler(
        _: Request,
        exception: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "detail": _sanitized_validation_errors(exception),
            },
        )

    application.include_router(
        health.router,
        tags=["Health"],
    )
    application.include_router(observability.router)
    application.include_router(
        admin_audit.router,
        tags=["Administration: audit"],
    )
    application.include_router(
        admin_projects.router,
        tags=["Administration: projects"],
    )
    application.include_router(
        admin_policies.router,
        tags=["Administration: policies"],
    )
    application.include_router(
        admin_webhooks.router,
        tags=["Administration: webhooks"],
    )
    application.include_router(
        policies.router,
        tags=["Policies"],
    )
    application.include_router(
        authorization.router,
        tags=["Authorization"],
    )
    application.include_router(
        decisions.router,
        tags=["Decisions"],
    )
    application.include_router(
        evidence.router,
        tags=["Evidence"],
    )
    application.include_router(
        integrity.router,
        tags=["Integrity"],
    )
    application.include_router(
        approvals.router,
        tags=["Approvals"],
    )
    application.include_router(
        execution_grants.router,
        tags=["Execution grants"],
    )

    return application


app = create_app()


__all__ = [
    "DATABASE_PATH",
    "app",
    "create_app",
    "evidence_store",
    "get_authenticated_project",
    "get_evidence_store",
    "lifespan",
    "require_admin_access",
]

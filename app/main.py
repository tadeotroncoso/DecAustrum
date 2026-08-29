from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI

from app.audit import SYSTEM_BOOTSTRAP_AUDIT_CONTEXT
from app.bootstrap import bootstrap_default_project
from app.dependencies import (
    DATABASE_PATH,
    evidence_store,
    get_authenticated_project,
    get_evidence_store,
    require_admin_access,
)
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID
from app.routers import (
    admin_audit,
    admin_policies,
    admin_projects,
    admin_webhooks,
    approvals,
    authorization,
    decisions,
    health,
    integrity,
    policies,
)
from app.security import get_configured_api_key


@asynccontextmanager
async def lifespan(_: FastAPI):
    api_key = get_configured_api_key()

    policy_templates = load_policies(
        POLICIES_DIRECTORY
    )
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

    yield


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(health.router)
app.include_router(admin_audit.router)
app.include_router(admin_projects.router)
app.include_router(admin_policies.router)
app.include_router(admin_webhooks.router)
app.include_router(policies.router)
app.include_router(authorization.router)
app.include_router(decisions.router)
app.include_router(integrity.router)
app.include_router(approvals.router)


__all__ = [
    "DATABASE_PATH",
    "app",
    "evidence_store",
    "get_authenticated_project",
    "get_evidence_store",
    "lifespan",
    "require_admin_access",
]

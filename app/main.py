from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4
import sqlite3

from typing import Annotated
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Query,
)
from app.api_keys import (
    ProjectApiKeyMetadata,
    ProjectApiKeyPage,
    ProjectApiKeyProvisioningResponse,
    ProjectApiKeyRecord,
    generate_project_api_key,
    get_api_key_prefix,
    hash_api_key,
)
from app.bootstrap import bootstrap_default_project

from app.idempotency import (
    IdempotencyRecord,
    build_request_fingerprint,
)

from app.approval_models import (
    ApprovalRecord,
    ApprovalRequestPage,
    ApprovalResolutionRequest,
    ApprovalResolutionStatus,
    ApprovalStatus,
)

from app.authorization_models import (
    AuthorizationDecisionPage,
    AuthorizationRequest,
    AuthorizationResponse,
)
from app.evidence_store import EvidenceStore
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalNotFoundError,
    InvalidPolicyContextError,
)
from app.policy_engine import (
    POLICIES_DIRECTORY,
    evaluate_policy,
)

from app.security import (
    admin_api_key_header,
    api_key_header,
    authenticate_admin,
    authenticate_project,
    get_configured_admin_api_key,
    get_configured_api_key,
)

from app.policy_loader import load_policies
from app.policy_models import Policy, PolicyPage

from app.project_models import (
    Project,
    ProjectCreateRequest,
    ProjectProvisioningResponse,
)

DATABASE_PATH = Path("data/regtrace.db")
evidence_store = EvidenceStore(DATABASE_PATH)

@asynccontextmanager
async def lifespan(_: FastAPI):
    api_key = get_configured_api_key()

    load_policies(POLICIES_DIRECTORY)
    evidence_store.initialize()

    bootstrap_default_project(
        store=evidence_store,
        api_key=api_key,
    )

    yield


app = FastAPI(
    title="RegTrace API",
    version="0.1.0",
    lifespan=lifespan,
)


def get_evidence_store() -> EvidenceStore:
    return evidence_store

def get_authenticated_project(
    provided_api_key: Annotated[
        str | None,
        Depends(api_key_header),
    ],
    store: EvidenceStore = Depends(get_evidence_store),
) -> Project:
    return authenticate_project(
        provided_api_key=provided_api_key,
        store=store,
    )


def require_admin_access(
    provided_api_key: Annotated[
        str | None,
        Depends(admin_api_key_header),
    ],
) -> None:
    authenticate_admin(
        provided_api_key=provided_api_key,
        configured_api_key=(
            get_configured_admin_api_key()
        ),
    )


def _get_project_or_404(
    project_id: UUID,
    store: EvidenceStore,
) -> Project:
    project = store.get_project(project_id)

    if project is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "project_not_found",
                "message": (
                    f"Project '{project_id}' was not found."
                ),
            },
        )

    return project

def get_active_policies() -> list[Policy]:
    return load_policies(POLICIES_DIRECTORY)

def _get_idempotent_authorization(
    store: EvidenceStore,
    idempotency_key: str,
    request_fingerprint: str,
    project_id: UUID,
) -> AuthorizationResponse | None:
    existing_record = store.get_idempotency_record(
        project_id=project_id,
        idempotency_key=idempotency_key,
    )

    if existing_record is None:
        return None

    if (
        existing_record.request_fingerprint
        != request_fingerprint
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "idempotency_key_conflict",
                "message": (
                    "Idempotency key has already been "
                    "used with a different request."
                ),
            },
        )

    authorization = store.get(
        decision_id=existing_record.decision_id,
        project_id=project_id,
    )

    if authorization is None:
        raise RuntimeError(
            "Idempotency record references a missing "
            "authorization decision."
        )

    return authorization


def _resolve_approval_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    status: ApprovalResolutionStatus,
    project_id: UUID,
    store: EvidenceStore,
) -> ApprovalRecord:
    try:
        return store.resolve_approval(
            decision_id=decision_id,
            project_id=project_id,
            status=status,
            resolved_by=resolution.resolved_by,
            resolved_at=datetime.now(timezone.utc),
        )
    except ApprovalNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "approval_not_found",
                "message": str(exc),
            },
        ) from exc
    except ApprovalAlreadyResolvedError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "approval_already_resolved",
                "message": str(exc),
                "current_status": exc.current_status,
            },
        ) from exc


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post(
    "/v1/admin/projects",
    response_model=ProjectProvisioningResponse,
    status_code=201,
    dependencies=[Depends(require_admin_access)],
)
def provision_project(
    request: ProjectCreateRequest,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectProvisioningResponse:
    created_at = datetime.now(timezone.utc)

    project = Project(
        project_id=uuid4(),
        name=request.name,
        status="ACTIVE",
        created_at=created_at,
    )

    api_key = generate_project_api_key()

    api_key_record = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=project.project_id,
        key_prefix=get_api_key_prefix(api_key),
        key_hash=hash_api_key(api_key),
        created_at=created_at,
    )

    store.save_project_with_api_key(
        project=project,
        api_key=api_key_record,
    )

    return ProjectProvisioningResponse(
        project=project,
        api_key=api_key,
    )


@app.post(
    "/v1/admin/projects/{project_id}/api-keys",
    response_model=ProjectApiKeyProvisioningResponse,
    status_code=201,
    dependencies=[Depends(require_admin_access)],
)
def provision_project_api_key(
    project_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectApiKeyProvisioningResponse:
    project = _get_project_or_404(
        project_id=project_id,
        store=store,
    )

    if project.status != "ACTIVE":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "project_disabled",
                "message": (
                    f"Project '{project_id}' is disabled."
                ),
            },
        )

    created_at = datetime.now(timezone.utc)
    api_key = generate_project_api_key()

    record = ProjectApiKeyRecord(
        api_key_id=uuid4(),
        project_id=project_id,
        key_prefix=get_api_key_prefix(api_key),
        key_hash=hash_api_key(api_key),
        created_at=created_at,
    )

    store.save_project_api_key(record)

    metadata = ProjectApiKeyMetadata(
        api_key_id=record.api_key_id,
        project_id=record.project_id,
        key_prefix=record.key_prefix,
        created_at=record.created_at,
        revoked_at=record.revoked_at,
    )

    return ProjectApiKeyProvisioningResponse(
        key=metadata,
        api_key=api_key,
    )


@app.get(
    "/v1/admin/projects/{project_id}/api-keys",
    response_model=ProjectApiKeyPage,
    dependencies=[Depends(require_admin_access)],
)
def list_project_api_keys(
    project_id: UUID,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectApiKeyPage:
    _get_project_or_404(
        project_id=project_id,
        store=store,
    )

    return ProjectApiKeyPage(
        items=store.list_project_api_keys(
            project_id=project_id,
            limit=limit,
            offset=offset,
        ),
        total=store.count_project_api_keys(project_id),
        limit=limit,
        offset=offset,
    )


@app.delete(
    (
        "/v1/admin/projects/{project_id}"
        "/api-keys/{api_key_id}"
    ),
    response_model=ProjectApiKeyMetadata,
    dependencies=[Depends(require_admin_access)],
)
def revoke_project_api_key(
    project_id: UUID,
    api_key_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> ProjectApiKeyMetadata:
    _get_project_or_404(
        project_id=project_id,
        store=store,
    )

    revoked_key = store.revoke_project_api_key(
        project_id=project_id,
        api_key_id=api_key_id,
        revoked_at=datetime.now(timezone.utc),
    )

    if revoked_key is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "api_key_not_found",
                "message": (
                    f"API key '{api_key_id}' was not found "
                    f"for project '{project_id}'."
                ),
            },
        )

    return revoked_key

@app.get(
    "/v1/policies",
    response_model=PolicyPage,
    dependencies=[Depends(get_authenticated_project)],
)
def list_active_policies(
    policies: list[Policy] = Depends(get_active_policies),
) -> PolicyPage:
    return PolicyPage(
        items=policies,
        total=len(policies),
    )


@app.get(
    "/v1/policies/{policy_id}",
    response_model=Policy,
    dependencies=[Depends(get_authenticated_project)],
)
def get_active_policy(
    policy_id: str,
    policies: list[Policy] = Depends(get_active_policies),
) -> Policy:
    for policy in policies:
        if policy.id == policy_id:
            return policy

    raise HTTPException(
        status_code=404,
        detail={
            "code": "policy_not_found",
            "message": (
                f"Policy '{policy_id}' was not found."
            ),
        },
    )


@app.post(
    "/v1/authorize",
    response_model=AuthorizationResponse,
)
def authorize(
    request: AuthorizationRequest,
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            min_length=1,
            max_length=255,
        ),
    ] = None,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationResponse:
    request_fingerprint = None

    if idempotency_key is not None:
        request_fingerprint = build_request_fingerprint(
            request
        )

        existing_authorization = (
            _get_idempotent_authorization(
                store=store,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                project_id=project.project_id,
            )
        )

        if existing_authorization is not None:
            return existing_authorization

    try:
        evaluation = evaluate_policy(
            request.action,
            request.context,
        )
    except InvalidPolicyContextError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_policy_context",
                "message": str(exc),
                "field": exc.field,
                "operator": exc.operator,
            },
        ) from exc

    authorization = AuthorizationResponse(
        decision_id=uuid4(),
        project_id=project.project_id,
        evaluated_at=datetime.now(timezone.utc),
        decision=evaluation.decision,
        policy=evaluation.policy_id,
        policy_version=evaluation.policy_version,
        reason=evaluation.reason,
        evidence=evaluation.evidence,
        agent=request.agent,
        action=request.action,
        context=request.context,
        trace=evaluation.trace,
    )

    approval = None

    if authorization.decision == "REQUIRE_APPROVAL":
        approval = ApprovalRecord(
            decision_id=authorization.decision_id,
            status="PENDING",
            requested_at=authorization.evaluated_at,
        )

    idempotency_record = None

    if (
        idempotency_key is not None
        and request_fingerprint is not None
    ):
        idempotency_record = IdempotencyRecord(
            project_id=project.project_id,
            idempotency_key=idempotency_key,
            request_fingerprint=request_fingerprint,
            decision_id=authorization.decision_id,
            created_at=authorization.evaluated_at,
        )

    try:
        store.save_authorization_with_approval(
            authorization=authorization,
            approval=approval,
            idempotency_record=idempotency_record,
        )
    except sqlite3.IntegrityError:
        if (
            idempotency_key is None
            or request_fingerprint is None
        ):
            raise

        existing_authorization = (
            _get_idempotent_authorization(
                store=store,
                idempotency_key=idempotency_key,
                request_fingerprint=request_fingerprint,
                project_id=project.project_id,
            )
        )

        if existing_authorization is None:
            raise

        return existing_authorization

    return authorization


@app.get(
    "/v1/decisions",
    response_model=AuthorizationDecisionPage,
)
def list_authorization_decisions(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationDecisionPage:
    return AuthorizationDecisionPage(
        items=store.list_decisions(
            project_id=project.project_id,
            limit=limit,
            offset=offset,
        ),
        total=store.count(
            project_id=project.project_id
        ),
        limit=limit,
        offset=offset,
    )


@app.get(
    "/v1/decisions/{decision_id}",
    response_model=AuthorizationResponse,
)
def get_authorization_decision(
    decision_id: UUID,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AuthorizationResponse:
    authorization = store.get(
        decision_id=decision_id,
        project_id=project.project_id,
    )

    if authorization is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "decision_not_found",
                "message": (
                    f"Decision '{decision_id}' was not found."
                ),
            },
        )

    return authorization


@app.get(
    "/v1/approvals",
    response_model=ApprovalRequestPage,
)
def list_approval_requests(
    status: ApprovalStatus | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRequestPage:
    return ApprovalRequestPage(
        items=store.list_approvals(
            project_id=project.project_id,
            status=status,
            limit=limit,
            offset=offset,
        ),
        total=store.count_approvals(
            project_id=project.project_id,
            status=status,
        ),
        limit=limit,
        offset=offset,
    )

@app.get(
    "/v1/approvals/{decision_id}",
    response_model=ApprovalRecord,
)
def get_approval_request(
    decision_id: UUID,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    approval = store.get_approval(
        decision_id=decision_id,
        project_id=project.project_id,
    )

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "approval_not_found",
                "message": (
                    f"Approval for decision "
                    f"'{decision_id}' was not found."
                ),
            },
        )

    return approval


@app.post(
    "/v1/approvals/{decision_id}/approve",
    response_model=ApprovalRecord,
)
def approve_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    return _resolve_approval_request(
        decision_id=decision_id,
        resolution=resolution,
        status="APPROVED",
        project_id=project.project_id,
        store=store,
    )


@app.post(
    "/v1/approvals/{decision_id}/reject",
    response_model=ApprovalRecord,
)
def reject_request(
    decision_id: UUID,
    resolution: ApprovalResolutionRequest,
    project: Project = Depends(
        get_authenticated_project
    ),
    store: EvidenceStore = Depends(get_evidence_store),
) -> ApprovalRecord:
    return _resolve_approval_request(
        decision_id=decision_id,
        resolution=resolution,
        status="REJECTED",
        project_id=project.project_id,
        store=store,
    )

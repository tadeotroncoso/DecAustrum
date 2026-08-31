from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from app.audit_models import (
    AdministrativeAuditEvent,
    AdministrativeAuditEventPage,
    AuditAction,
    AuditActorType,
    AuditResourceType,
)
from app.dependencies import (
    get_evidence_store,
    require_admin_access,
)
from app.evidence_store import EvidenceStore

router = APIRouter()


@router.get(
    "/v1/admin/audit-events",
    response_model=AdministrativeAuditEventPage,
    dependencies=[Depends(require_admin_access)],
)
def list_administrative_audit_events(
    project_id: UUID | None = Query(default=None),
    action: AuditAction | None = Query(default=None),
    resource_type: AuditResourceType | None = Query(
        default=None
    ),
    resource_id: str | None = Query(default=None, min_length=1),
    actor_type: AuditActorType | None = Query(default=None),
    actor_id: str | None = Query(default=None, min_length=1),
    occurred_after: datetime | None = Query(default=None),
    occurred_before: datetime | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    store: EvidenceStore = Depends(get_evidence_store),
) -> AdministrativeAuditEventPage:
    for parameter_name, timestamp in (
        ("occurred_after", occurred_after),
        ("occurred_before", occurred_before),
    ):
        if timestamp is not None and timestamp.tzinfo is None:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "audit_timezone_required",
                    "message": (
                        f"Query parameter '{parameter_name}' "
                        "must include a timezone."
                    ),
                    "parameter": parameter_name,
                },
            )

    if (
        occurred_after is not None
        and occurred_before is not None
        and occurred_after > occurred_before
    ):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_audit_time_range",
                "message": (
                    "occurred_after must be earlier than or "
                    "equal to occurred_before."
                ),
            },
        )

    items = store.list_administrative_audit_events(
        project_id=project_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_type=actor_type,
        actor_id=actor_id,
        occurred_after=occurred_after,
        occurred_before=occurred_before,
        limit=limit,
        offset=offset,
    )

    return AdministrativeAuditEventPage(
        items=items,
        total=store.count_administrative_audit_events(
            project_id=project_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_after=occurred_after,
            occurred_before=occurred_before,
        ),
        limit=limit,
        offset=offset,
    )


@router.get(
    "/v1/admin/audit-events/{event_id}",
    response_model=AdministrativeAuditEvent,
    dependencies=[Depends(require_admin_access)],
)
def get_administrative_audit_event(
    event_id: UUID,
    store: EvidenceStore = Depends(get_evidence_store),
) -> AdministrativeAuditEvent:
    event = store.get_administrative_audit_event(event_id)

    if event is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "audit_event_not_found",
                "message": (
                    f"Administrative audit event "
                    f"'{event_id}' was not found."
                ),
            },
        )

    return event

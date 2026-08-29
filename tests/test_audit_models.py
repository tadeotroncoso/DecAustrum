from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.audit_models import (
    AdministrativeAuditEvent,
    AuditContext,
)


def test_audit_context_normalizes_identity_and_reason():
    context = AuditContext(
        actor_type="ADMIN",
        actor_id="  security-admin  ",
        reason="  Emergency key rotation  ",
    )

    assert context.actor_id == "security-admin"
    assert context.reason == "Emergency key rotation"


def test_audit_event_requires_timezone_aware_timestamp():
    with pytest.raises(
        ValidationError,
        match="occurred_at must include a timezone",
    ):
        AdministrativeAuditEvent(
            event_id=uuid4(),
            occurred_at=datetime(2026, 8, 29, 12, 0),
            project_id=uuid4(),
            actor_type="ADMIN",
            actor_id="security-admin",
            action="PROJECT_CREATED",
            resource_type="PROJECT",
            resource_id=str(uuid4()),
        )


def test_audit_event_rejects_unknown_action():
    with pytest.raises(ValidationError):
        AdministrativeAuditEvent(
            event_id=uuid4(),
            occurred_at=datetime.now(timezone.utc),
            project_id=uuid4(),
            actor_type="ADMIN",
            actor_id="security-admin",
            action="BANANA",
            resource_type="PROJECT",
            resource_id=str(uuid4()),
        )

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.approval_models import ApprovalRecord


def test_pending_approval_has_no_resolution():
    approval = ApprovalRecord(
        decision_id=uuid4(),
        status="PENDING",
        requested_at=datetime.now(timezone.utc),
    )

    assert approval.status == "PENDING"
    assert approval.resolved_at is None
    assert approval.resolved_by is None


def test_expired_approval_requires_resolution_data():
    requested_at = datetime.now(timezone.utc)
    approval = ApprovalRecord(
        decision_id=uuid4(),
        status="EXPIRED",
        requested_at=requested_at,
        expires_at=requested_at + timedelta(minutes=1),
        resolved_at=requested_at + timedelta(minutes=2),
        resolved_by="regtrace-expiration",
    )

    assert approval.status == "EXPIRED"


def test_approval_rejects_invalid_expiration_window():
    requested_at = datetime.now(timezone.utc)

    with pytest.raises(ValidationError):
        ApprovalRecord(
            decision_id=uuid4(),
            status="PENDING",
            requested_at=requested_at,
            expires_at=requested_at,
        )


def test_approval_rejects_unknown_status():
    with pytest.raises(ValidationError):
        ApprovalRecord(
            decision_id=uuid4(),
            status="BANANA",
            requested_at=datetime.now(timezone.utc),
        )

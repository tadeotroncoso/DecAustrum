from datetime import datetime, timezone
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


def test_approval_rejects_unknown_status():
    with pytest.raises(ValidationError):
        ApprovalRecord(
            decision_id=uuid4(),
            status="BANANA",
            requested_at=datetime.now(timezone.utc),
        )
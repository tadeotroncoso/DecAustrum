from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.project_models import (
    Project,
    ProjectCreateRequest,
    ProjectStatusUpdateRequest,
)


def test_project_accepts_valid_data():
    timestamp = datetime.now(timezone.utc)

    project = Project(
        project_id=uuid4(),
        name="  Acme Production  ",
        created_at=timestamp,
    )

    assert project.name == "Acme Production"
    assert project.status == "ACTIVE"
    assert project.updated_at == timestamp


def test_project_rejects_empty_name():
    with pytest.raises(ValidationError):
        Project(
            project_id=uuid4(),
            name="   ",
            created_at=datetime.now(timezone.utc),
        )


def test_project_rejects_invalid_status():
    with pytest.raises(ValidationError):
        Project(
            project_id=uuid4(),
            name="Acme Production",
            status="UNKNOWN",
            created_at=datetime.now(timezone.utc),
        )

def test_project_create_request_normalizes_name():
    request = ProjectCreateRequest(
        name="  Acme Production  "
    )

    assert request.name == "Acme Production"


def test_project_create_request_rejects_empty_name():
    with pytest.raises(ValidationError):
        ProjectCreateRequest(name="   ")


def test_project_status_update_accepts_known_status():
    request = ProjectStatusUpdateRequest(
        status="DISABLED"
    )

    assert request.status == "DISABLED"


def test_project_status_update_rejects_unknown_status():
    with pytest.raises(ValidationError):
        ProjectStatusUpdateRequest(status="UNKNOWN")

import pytest
from pydantic import ValidationError

from app.policy_models import Policy


def test_policy_version_must_be_positive():
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {
                "id": "test-policy",
                "version": 0,
                "action": "test-action",
                "condition": {
                    "field": "amount",
                    "operator": "greater_than",
                    "value": 100,
                },
                "decision": "DENY",
                "reason": "Test reason.",
            }
        )
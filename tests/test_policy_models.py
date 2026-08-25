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


def test_policy_accepts_multiple_conditions():
    policy = Policy.model_validate(
        {
            "id": "high-risk-data-export",
            "version": 1,
            "action": "export_customer_data",
            "match": "all",
            "conditions": [
                {
                    "field": "record_count",
                    "operator": "greater_than",
                    "value": 1000,
                },
                {
                    "field": "destination_region",
                    "operator": "not_equals",
                    "value": "EU",
                },
            ],
            "decision": "DENY",
            "reason": (
                "Large data exports outside the EU are denied."
            ),
        }
    )

    assert policy.match == "all"
    assert len(policy.conditions) == 2
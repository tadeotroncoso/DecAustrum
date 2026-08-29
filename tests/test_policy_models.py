from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.policy_models import Policy, ProjectPolicyVersion


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


def build_historical_policy() -> dict:
    return {
        "id": "refund-limit",
        "version": 2,
        "action": "refund_payment",
        "match": "all",
        "conditions": [
            {
                "field": "amount",
                "operator": "greater_than",
                "value": 500,
            }
        ],
        "decision": "REQUIRE_APPROVAL",
        "reason": "Large refunds require approval.",
    }


def test_historical_policy_identity_must_match_payload():
    with pytest.raises(
        ValidationError,
        match="Historical policy version must match version",
    ):
        ProjectPolicyVersion.model_validate(
            {
                "project_id": uuid4(),
                "policy_id": "refund-limit",
                "version": 1,
                "policy": build_historical_policy(),
                "change_type": "UPDATED",
                "created_at": datetime.now(timezone.utc),
            }
        )


def test_rollback_history_requires_source_version():
    with pytest.raises(
        ValidationError,
        match="Rollback versions require source_version",
    ):
        ProjectPolicyVersion.model_validate(
            {
                "project_id": uuid4(),
                "policy_id": "refund-limit",
                "version": 2,
                "policy": build_historical_policy(),
                "change_type": "ROLLBACK",
                "created_at": datetime.now(timezone.utc),
            }
        )


def test_non_rollback_history_rejects_source_version():
    with pytest.raises(
        ValidationError,
        match="Only rollback versions may have source_version",
    ):
        ProjectPolicyVersion.model_validate(
            {
                "project_id": uuid4(),
                "policy_id": "refund-limit",
                "version": 2,
                "policy": build_historical_policy(),
                "change_type": "UPDATED",
                "source_version": 1,
                "created_at": datetime.now(timezone.utc),
            }
        )

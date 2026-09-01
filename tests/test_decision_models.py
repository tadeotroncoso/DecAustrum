import pytest
from pydantic import ValidationError

from app.decision_models import ConditionEvidence


@pytest.mark.parametrize(
    "field_name",
    ["actual_value", "expected_value"],
)
@pytest.mark.parametrize(
    "invalid_value",
    [float("nan"), float("inf"), float("-inf")],
)
def test_condition_evidence_rejects_non_finite_json_values(
    field_name,
    invalid_value,
):
    evidence = {
        "field": "amount",
        "operator": "greater_than",
        "actual_value": 100,
        "expected_value": 50,
        "matched": True,
    }
    evidence[field_name] = invalid_value

    with pytest.raises(ValidationError, match="finite JSON"):
        ConditionEvidence.model_validate(evidence)

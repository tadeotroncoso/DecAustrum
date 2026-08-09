from pathlib import Path
from typing import Any

from app.policy_loader import load_policy


POLICY_PATH = Path("policies/refund_limit.yaml")


def evaluate_policy(action: str, context: dict[str, Any]) -> str:
    policy = load_policy(POLICY_PATH)

    if action != policy["action"]:
        return "ALLOW"

    condition = policy["condition"]

    field = condition["field"]
    operator = condition["operator"]
    expected_value = condition["value"]

    actual_value = context.get(field)

    if (
        operator == "greater_than"
        and actual_value is not None
        and actual_value > expected_value
    ):
        return policy["decision"]

    return "ALLOW"
from pathlib import Path
from typing import Any

from app.operators import evaluate_operator
from app.policy_loader import load_policies


POLICIES_DIRECTORY = Path("policies")

DECISION_PRIORITY = {
    "ALLOW": 0,
    "REQUIRE_APPROVAL": 1,
    "DENY": 2,
}


def evaluate_policy(action: str, context: dict[str, Any]) -> str:
    policies = load_policies(POLICIES_DIRECTORY)

    final_decision = "ALLOW"

    for policy in policies:
        if action != policy["action"]:
            continue

        condition = policy["condition"]

        field = condition["field"]
        operator = condition["operator"]
        expected_value = condition["value"]

        actual_value = context.get(field)

        if (
            actual_value is not None
            and evaluate_operator(
                operator,
                actual_value,
                expected_value,
            )
        ):
            policy_decision = policy["decision"]

            if (
                DECISION_PRIORITY[policy_decision]
                > DECISION_PRIORITY[final_decision]
            ):
                final_decision = policy_decision

    return final_decision
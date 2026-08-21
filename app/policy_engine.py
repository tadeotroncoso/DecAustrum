from pathlib import Path
from typing import Any

from app.operators import evaluate_operator
from app.policy_loader import load_policies
from app.decision_models import PolicyEvaluation


POLICIES_DIRECTORY = Path("policies")

DECISION_PRIORITY = {
    "ALLOW": 0,
    "REQUIRE_APPROVAL": 1,
    "DENY": 2,
}


def evaluate_policy(
    action: str,
    context: dict[str, Any],
) -> PolicyEvaluation:

    policies = load_policies(POLICIES_DIRECTORY)

    final_decision = "ALLOW"
    winning_policy_id = None

    for policy in policies:
        if action != policy.action:
            continue

        condition = policy.condition

        actual_value = context.get(condition.field)

        if (
            actual_value is not None
            and evaluate_operator(
                condition.operator,
                actual_value,
                condition.value,
            )
        ):
            policy_decision = policy.decision

            if (
                DECISION_PRIORITY[policy_decision]
                > DECISION_PRIORITY[final_decision]
            ):
                final_decision = policy_decision
                winning_policy_id = policy.id

    return PolicyEvaluation(
    decision=final_decision,
    policy_id=winning_policy_id,
    )
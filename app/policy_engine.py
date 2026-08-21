from pathlib import Path
from typing import Any

from app.operators import evaluate_operator
from app.policy_loader import load_policies
from app.decision_models import ConditionEvidence, PolicyEvaluation
from app.exceptions import InvalidPolicyContextError


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
    winning_reason = "No policy required approval or denial."
    winning_evidence = None

    for policy in policies:
        if action != policy.action:
            continue

        condition = policy.condition
        actual_value = context.get(condition.field)

        if actual_value is None:
            continue

        try:
            condition_matches = evaluate_operator(
                condition.operator,
                actual_value,
                condition.value,
            )
        except TypeError as exc:
            raise InvalidPolicyContextError(
                field=condition.field,
                operator=condition.operator,
            ) from exc

        if not condition_matches:
            continue

        policy_decision = policy.decision

        if (
            DECISION_PRIORITY[policy_decision]
            > DECISION_PRIORITY[final_decision]
        ):
            final_decision = policy_decision
            winning_policy_id = policy.id
            winning_reason = policy.reason
            winning_evidence = ConditionEvidence(
                field=condition.field,
                operator=condition.operator,
                actual_value=actual_value,
                expected_value=condition.value,
            )

    return PolicyEvaluation(
        decision=final_decision,
        policy_id=winning_policy_id,
        reason=winning_reason,
        evidence=winning_evidence,
    )
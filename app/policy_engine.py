from pathlib import Path
from typing import Any

from app.operators import evaluate_operator
from app.policy_loader import load_policies
from app.decision_models import (
    ConditionEvidence,
    PolicyEvaluation,
    PolicyEvidence,
)
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
    winning_policy_version = None
    winning_reason = "No policy required approval or denial."
    winning_evidence = None

    for policy in policies:
        if action != policy.action:
            continue

        condition_results = []
        condition_evidence = []

        for condition in policy.conditions:
            actual_value = context.get(condition.field)

            if actual_value is None:
                condition_matches = False
            else:
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

            condition_results.append(condition_matches)

            condition_evidence.append(
                ConditionEvidence(
                    field=condition.field,
                    operator=condition.operator,
                    actual_value=actual_value,
                    expected_value=condition.value,
                    matched=condition_matches,
                )
            )

        if policy.match == "all":
            policy_matches = all(condition_results)
        else:
            policy_matches = any(condition_results)

        if not policy_matches:
            continue

        policy_decision = policy.decision

        if (
            DECISION_PRIORITY[policy_decision]
            > DECISION_PRIORITY[final_decision]
        ):
            final_decision = policy_decision
            winning_policy_id = policy.id
            winning_policy_version = policy.version
            winning_reason = policy.reason
            winning_evidence = PolicyEvidence(
                match=policy.match,
                conditions=condition_evidence,
            )

    return PolicyEvaluation(
        decision=final_decision,
        policy_id=winning_policy_id,
        policy_version=winning_policy_version,
        reason=winning_reason,
        evidence=winning_evidence,
    )
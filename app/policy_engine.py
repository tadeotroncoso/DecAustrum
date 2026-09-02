from pathlib import Path
from typing import Any

from app.decision_models import (
    ConditionEvidence,
    PolicyEvaluation,
    PolicyEvidence,
    PolicyTraceEntry,
)
from app.exceptions import (
    InvalidPolicyContextError,
    MissingPolicyContextError,
)
from app.operators import evaluate_operator
from app.policy_loader import load_policies
from app.policy_models import Policy
from app.policy_types import Decision

POLICIES_DIRECTORY = Path("policies")

DECISION_PRIORITY = {
    "ALLOW": 0,
    "REQUIRE_APPROVAL": 1,
    "DENY": 2,
}


def evaluate_policy(
    action: str,
    context: dict[str, Any],
    *,
    policies: list[Policy] | None = None,
) -> PolicyEvaluation:
    if policies is None:
        policies = load_policies(POLICIES_DIRECTORY)

    applicable_policies = [
        policy
        for policy in policies
        if policy.action == action
    ]

    if not applicable_policies:
        return PolicyEvaluation(
            decision="DENY",
            policy_id=None,
            policy_version=None,
            reason=(
                f"Action '{action}' is not covered by an active policy."
            ),
            evidence=None,
            trace=[],
        )

    final_decision: Decision = "ALLOW"
    winning_policy_id = None
    winning_policy_version = None
    winning_reason = "No policy required approval or denial."
    winning_evidence = None
    policy_trace = []

    for policy in applicable_policies:
        condition_results = []
        condition_evidence = []

        for condition in policy.conditions:
            actual_value = context.get(condition.field)

            if actual_value is None:
                raise MissingPolicyContextError(
                    field=condition.field,
                    policy_id=policy.id,
                )

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

        policy_evidence = PolicyEvidence(
            match=policy.match,
            conditions=condition_evidence,
        )

        policy_trace.append(
            PolicyTraceEntry(
                policy_id=policy.id,
                policy_version=policy.version,
                decision=policy.decision,
                reason=policy.reason,
                matched=policy_matches,
                evidence=policy_evidence,
            )
        )

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
        trace=policy_trace,
    )

from typing import Any


def evaluate_policy(action: str, context: dict[str, Any]) -> str:
    if (
        action == "refund_payment"
        and context.get("amount", 0) > 500
    ):
        return "REQUIRE_APPROVAL"

    return "ALLOW"
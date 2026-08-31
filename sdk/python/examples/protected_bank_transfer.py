"""Run a bank transfer only after DecAustrum authorizes it.

Start the local API first, configure DECAUSTRUM_API_KEY and
DECAUSTRUM_BASE_URL, then run this file. The inline approval is deliberately a
demo shortcut; production reviewers should approve through a separate trusted
workflow and pass the short-lived grant to the execution runtime securely.
"""

from decaustrum import (
    ActionDeniedError,
    ApprovalRequiredError,
    DecAustrumClient,
    DecAustrumGuard,
)


AGENT = "finance-agent"
ACTION = "bank_transfer"
CONTEXT = {
    "amount": 25_000,
    "account_verified": True,
}


def perform_bank_transfer() -> dict[str, object]:
    """Stand-in for the side-effecting business operation."""

    print("Bank transfer executed exactly once.")
    return {"status": "submitted", "amount": CONTEXT["amount"]}


def main() -> None:
    with DecAustrumClient.from_environment() as client:
        guard = DecAustrumGuard(client)

        try:
            result = guard.execute(
                agent=AGENT,
                action=ACTION,
                context=CONTEXT,
                operation=perform_bank_transfer,
                idempotency_key="example-bank-transfer-001",
            )
        except ActionDeniedError as exc:
            print(f"Blocked by policy: {exc.decision.reason}")
            return
        except ApprovalRequiredError as exc:
            print(
                "Approval required for decision "
                f"{exc.decision.decision_id}."
            )

            # Demo only: use a separate reviewer workflow in production.
            grant = client.approve(
                exc.decision.decision_id,
                resolved_by="example-security-reviewer",
                reason="Approved by the SDK integration example.",
            )
            result = guard.execute_approved(
                execution_grant=grant.execution_grant,
                agent=AGENT,
                action=ACTION,
                context=CONTEXT,
                consumed_by="example-finance-runtime",
                operation=perform_bank_transfer,
            )

        print(result.value)


if __name__ == "__main__":
    main()

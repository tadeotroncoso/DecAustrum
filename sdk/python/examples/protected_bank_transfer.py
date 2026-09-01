"""Run a bank transfer only after DecAustrum authorizes it.

Start the local API first, configure separate DECAUSTRUM_API_KEY and
DECAUSTRUM_REVIEWER_API_KEY values plus DECAUSTRUM_BASE_URL, then run this
file. Production reviewers should approve through a separate trusted workflow
and pass the short-lived grant to the execution runtime securely.
"""

import os

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
    base_url = os.getenv(
        "DECAUSTRUM_BASE_URL",
        "http://localhost:8000",
    )
    reviewer_api_key = os.environ["DECAUSTRUM_REVIEWER_API_KEY"]

    with (
        DecAustrumClient.from_environment() as client,
        DecAustrumClient(
            api_key=reviewer_api_key,
            base_url=base_url,
        ) as reviewer,
    ):
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

            grant = reviewer.approve(
                exc.decision.decision_id,
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

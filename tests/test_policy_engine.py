from app.policy_engine import evaluate_policy


def test_small_refund_is_allowed():
    decision = evaluate_policy(
        "refund_payment",
        {"amount": 300},
    )

    assert decision == "ALLOW"


def test_large_refund_requires_approval():
    decision = evaluate_policy(
        "refund_payment",
        {"amount": 750},
    )

    assert decision == "REQUIRE_APPROVAL"


def test_small_bank_transfer_is_allowed():
    decision = evaluate_policy(
        "bank_transfer",
        {"amount": 5000},
    )

    assert decision == "ALLOW"


def test_large_bank_transfer_requires_approval():
    decision = evaluate_policy(
        "bank_transfer",
        {"amount": 25000},
    )

    assert decision == "REQUIRE_APPROVAL"


def test_unknown_action_is_allowed():
    decision = evaluate_policy(
        "send_email",
        {"recipient": "test@example.com"},
    )

    assert decision == "ALLOW"
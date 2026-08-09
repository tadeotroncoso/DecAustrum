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
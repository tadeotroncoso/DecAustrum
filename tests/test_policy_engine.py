from app.policy_engine import evaluate_policy


def test_small_refund_is_allowed():
    decision, policy_id = evaluate_policy(
        "refund_payment",
        {"amount": 300},
    )

    assert decision == "ALLOW"
    assert policy_id is None


def test_large_refund_requires_approval():
    decision, policy_id = evaluate_policy(
        "refund_payment",
        {"amount": 750},
    )

    assert decision == "REQUIRE_APPROVAL"
    assert policy_id == "refund-limit"


def test_small_bank_transfer_is_allowed():
    decision, policy_id = evaluate_policy(
        "bank_transfer",
        {
            "amount": 5000,
            "account_verified": True,
        },
    )

    assert decision == "ALLOW"
    assert policy_id is None


def test_large_bank_transfer_requires_approval():
    decision, policy_id = evaluate_policy(
        "bank_transfer",
        {
            "amount": 25000,
            "account_verified": True,
        },
    )

    assert decision == "REQUIRE_APPROVAL"
    assert policy_id == "large-transfer"


def test_unknown_action_is_allowed():
    decision, policy_id = evaluate_policy(
        "send_email",
        {"recipient": "test@example.com"},
    )

    assert decision == "ALLOW"
    assert policy_id is None


def test_unverified_account_is_denied():
    decision, policy_id = evaluate_policy(
        "bank_transfer",
        {
            "amount": 5000,
            "account_verified": False,
        },
    )

    assert decision == "DENY"
    assert policy_id == "unverified-account"


def test_deny_overrides_require_approval():
    decision, policy_id = evaluate_policy(
        "bank_transfer",
        {
            "amount": 25000,
            "account_verified": False,
        },
    )

    assert decision == "DENY"
    assert policy_id == "unverified-account"


def test_verified_large_transfer_requires_approval():
    decision, policy_id = evaluate_policy(
        "bank_transfer",
        {
            "amount": 25000,
            "account_verified": True,
        },
    )

    assert decision == "REQUIRE_APPROVAL"
    assert policy_id == "large-transfer"
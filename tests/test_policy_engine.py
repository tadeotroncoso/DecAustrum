from app.policy_engine import evaluate_policy


def test_small_refund_is_allowed():
    evaluation = evaluate_policy(
        "refund_payment",
        {"amount": 300},
    )

    assert evaluation.decision == "ALLOW"
    assert evaluation.policy_id is None


def test_large_refund_requires_approval():
    evaluation = evaluate_policy(
        "refund_payment",
        {"amount": 750},
    )

    assert evaluation.decision == "REQUIRE_APPROVAL"
    assert evaluation.policy_id == "refund-limit"


def test_small_bank_transfer_is_allowed():
    evaluation = evaluate_policy(
        "bank_transfer",
        {
            "amount": 5000,
            "account_verified": True,
        },
    )

    assert evaluation.decision == "ALLOW"
    assert evaluation.policy_id is None


def test_large_bank_transfer_requires_approval():
    evaluation = evaluate_policy(
        "bank_transfer",
        {
            "amount": 25000,
            "account_verified": True,
        },
    )

    assert evaluation.decision == "REQUIRE_APPROVAL"
    assert evaluation.policy_id == "large-transfer"


def test_unknown_action_is_allowed():
    evaluation = evaluate_policy(
        "send_email",
        {"recipient": "test@example.com"},
    )

    assert evaluation.decision == "ALLOW"
    assert evaluation.policy_id is None


def test_unverified_account_is_denied():
    evaluation = evaluate_policy(
        "bank_transfer",
        {
            "amount": 5000,
            "account_verified": False,
        },
    )

    assert evaluation.decision == "DENY"
    assert evaluation.policy_id == "unverified-account"


def test_deny_overrides_require_approval():
    evaluation = evaluate_policy(
        "bank_transfer",
        {
            "amount": 25000,
            "account_verified": False,
        },
    )

    assert evaluation.decision == "DENY"
    assert evaluation.policy_id == "unverified-account"


def test_verified_large_transfer_requires_approval():
    evaluation = evaluate_policy(
        "bank_transfer",
        {
            "amount": 25000,
            "account_verified": True,
        },
    )

    assert evaluation.decision == "REQUIRE_APPROVAL"
    assert evaluation.policy_id == "large-transfer"


def test_all_conditions_must_match():
    evaluation = evaluate_policy(
        "export_customer_data",
        {
            "record_count": 5000,
            "destination_region": "US",
        },
    )

    assert evaluation.decision == "DENY"
    assert evaluation.policy_id == "high-risk-data-export"
    assert evaluation.evidence is not None
    assert evaluation.evidence.match == "all"

    assert [
        condition.matched
        for condition in evaluation.evidence.conditions
    ] == [True, True]


def test_all_policy_does_not_match_when_one_condition_fails():
    evaluation = evaluate_policy(
        "export_customer_data",
        {
            "record_count": 5000,
            "destination_region": "EU",
        },
    )

    assert evaluation.decision == "ALLOW"
    assert evaluation.policy_id is None
    assert evaluation.evidence is None


def test_any_policy_matches_when_one_condition_matches():
    evaluation = evaluate_policy(
        "access_customer_record",
        {
            "classification": "public",
            "contains_personal_data": True,
        },
    )

    assert evaluation.decision == "REQUIRE_APPROVAL"
    assert evaluation.policy_id == "sensitive-record-access"
    assert evaluation.evidence is not None
    assert evaluation.evidence.match == "any"

    assert [
        condition.matched
        for condition in evaluation.evidence.conditions
    ] == [False, True]


def test_any_policy_fails_when_no_conditions_match():
    evaluation = evaluate_policy(
        "access_customer_record",
        {
            "classification": "public",
            "contains_personal_data": False,
        },
    )

    assert evaluation.decision == "ALLOW"
    assert evaluation.policy_id is None
    assert evaluation.evidence is None

def test_trace_records_all_matching_candidates():
    evaluation = evaluate_policy(
        "bank_transfer",
        {
            "amount": 25000,
            "account_verified": False,
        },
    )

    trace_by_policy = {
        entry.policy_id: entry
        for entry in evaluation.trace
    }

    assert evaluation.decision == "DENY"

    assert trace_by_policy["large-transfer"].matched is True
    assert (
        trace_by_policy["large-transfer"].decision
        == "REQUIRE_APPROVAL"
    )

    assert trace_by_policy["unverified-account"].matched is True
    assert (
        trace_by_policy["unverified-account"].decision
        == "DENY"
    )


def test_trace_records_candidates_that_do_not_match():
    evaluation = evaluate_policy(
        "bank_transfer",
        {
            "amount": 5000,
            "account_verified": True,
        },
    )

    trace_by_policy = {
        entry.policy_id: entry
        for entry in evaluation.trace
    }

    assert evaluation.decision == "ALLOW"
    assert trace_by_policy["large-transfer"].matched is False
    assert trace_by_policy["unverified-account"].matched is False
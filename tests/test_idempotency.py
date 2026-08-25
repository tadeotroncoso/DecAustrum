from app.authorization_models import AuthorizationRequest
from app.idempotency import build_request_fingerprint


def test_same_request_produces_same_fingerprint():
    first_request = AuthorizationRequest(
        agent="finance-agent",
        action="bank_transfer",
        context={
            "amount": 5000,
            "account_verified": True,
        },
    )

    second_request = AuthorizationRequest(
        agent="finance-agent",
        action="bank_transfer",
        context={
            "account_verified": True,
            "amount": 5000,
        },
    )

    assert (
        build_request_fingerprint(first_request)
        == build_request_fingerprint(second_request)
    )


def test_different_request_produces_different_fingerprint():
    first_request = AuthorizationRequest(
        agent="finance-agent",
        action="bank_transfer",
        context={"amount": 5000},
    )

    second_request = AuthorizationRequest(
        agent="finance-agent",
        action="bank_transfer",
        context={"amount": 5001},
    )

    assert (
        build_request_fingerprint(first_request)
        != build_request_fingerprint(second_request)
    )
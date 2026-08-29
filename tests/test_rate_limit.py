import pytest

from app.rate_limit import (
    FixedWindowRateLimiter,
    rate_limit_subject,
)


def test_fixed_window_rate_limiter_enforces_limit():
    limiter = FixedWindowRateLimiter()

    first = limiter.check(
        policy="authorize",
        subject="client-a",
        limit=2,
        window_seconds=60,
        now=10,
    )
    second = limiter.check(
        policy="authorize",
        subject="client-a",
        limit=2,
        window_seconds=60,
        now=11,
    )
    denied = limiter.check(
        policy="authorize",
        subject="client-a",
        limit=2,
        window_seconds=60,
        now=12,
    )

    assert first.allowed is True
    assert first.remaining == 1
    assert second.allowed is True
    assert second.remaining == 0
    assert denied.allowed is False
    assert denied.remaining == 0
    assert denied.reset_at == 60
    assert denied.retry_after == 48


def test_fixed_window_rate_limiter_resets_next_window():
    limiter = FixedWindowRateLimiter()
    limiter.check(
        policy="authorize",
        subject="client-a",
        limit=1,
        window_seconds=60,
        now=59,
    )

    reset = limiter.check(
        policy="authorize",
        subject="client-a",
        limit=1,
        window_seconds=60,
        now=60,
    )

    assert reset.allowed is True
    assert reset.remaining == 0
    assert reset.reset_at == 120


def test_rate_limit_buckets_are_isolated_by_policy_and_subject():
    limiter = FixedWindowRateLimiter()
    limiter.check(
        policy="tenant",
        subject="client-a",
        limit=1,
        window_seconds=60,
        now=1,
    )

    other_subject = limiter.check(
        policy="tenant",
        subject="client-b",
        limit=1,
        window_seconds=60,
        now=2,
    )
    other_policy = limiter.check(
        policy="admin",
        subject="client-a",
        limit=1,
        window_seconds=60,
        now=2,
    )

    assert other_subject.allowed is True
    assert other_policy.allowed is True


def test_rate_limit_clear_removes_existing_buckets():
    limiter = FixedWindowRateLimiter()
    limiter.check(
        policy="tenant",
        subject="client-a",
        limit=1,
        window_seconds=60,
        now=1,
    )
    limiter.clear()

    decision = limiter.check(
        policy="tenant",
        subject="client-a",
        limit=1,
        window_seconds=60,
        now=2,
    )

    assert decision.allowed is True


@pytest.mark.parametrize(
    ("limit", "window_seconds"),
    [(0, 60), (-1, 60), (1, 0), (1, -1)],
)
def test_rate_limiter_rejects_invalid_configuration(
    limit,
    window_seconds,
):
    with pytest.raises(ValueError):
        FixedWindowRateLimiter().check(
            policy="tenant",
            subject="client-a",
            limit=limit,
            window_seconds=window_seconds,
        )


def test_rate_limit_subject_never_contains_raw_credentials():
    secret = "regtrace-secret-api-key"

    subject = rate_limit_subject(
        credential=secret,
        client_host="127.0.0.1",
    )

    assert len(subject) == 64
    assert secret not in subject
    assert subject == rate_limit_subject(
        credential=secret,
        client_host="203.0.113.2",
    )


def test_anonymous_rate_limit_subject_is_stable_per_client():
    first = rate_limit_subject(
        credential=None,
        client_host="192.0.2.1",
    )
    second = rate_limit_subject(
        credential=None,
        client_host="192.0.2.2",
    )

    assert first != second

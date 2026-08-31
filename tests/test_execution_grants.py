from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.exceptions import InvalidExecutionGrantError
from app.execution_grants import (
    build_execution_grant_token,
    hash_execution_grant_token,
    parse_execution_grant_token,
)
from app.execution_models import ExecutionGrantPayload

SECRET = "execution-grant-test-secret-at-least-32-bytes"


def build_payload() -> ExecutionGrantPayload:
    issued_at = datetime.now(timezone.utc)
    return ExecutionGrantPayload(
        grant_id=uuid4(),
        decision_id=uuid4(),
        project_id=uuid4(),
        request_fingerprint="a" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )


def test_execution_grant_round_trip_is_deterministic():
    payload = build_payload()

    first = build_execution_grant_token(payload, SECRET)
    second = build_execution_grant_token(payload, SECRET)
    parsed = parse_execution_grant_token(first, SECRET)

    assert first == second
    assert parsed == payload
    assert len(hash_execution_grant_token(first)) == 64


@pytest.mark.parametrize("part", [0, 1, 2])
def test_execution_grant_rejects_tampering(part):
    token = build_execution_grant_token(build_payload(), SECRET)
    pieces = token.split(".")
    pieces[part] = pieces[part][:-1] + (
        "A" if pieces[part][-1] != "A" else "B"
    )

    with pytest.raises(InvalidExecutionGrantError):
        parse_execution_grant_token(".".join(pieces), SECRET)


def test_execution_grant_rejects_wrong_secret():
    token = build_execution_grant_token(build_payload(), SECRET)

    with pytest.raises(InvalidExecutionGrantError):
        parse_execution_grant_token(
            token,
            "different-execution-secret-at-least-32-bytes",
        )


def test_execution_grant_rejects_noncanonical_signature_encoding():
    token = build_execution_grant_token(build_payload(), SECRET)
    pieces = token.split(".")
    alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_"
    )
    last_index = alphabet.index(pieces[2][-1])

    pieces[2] = pieces[2][:-1] + alphabet[last_index ^ 1]

    with pytest.raises(InvalidExecutionGrantError):
        parse_execution_grant_token(".".join(pieces), SECRET)


def test_execution_grant_rejects_weak_secret():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        build_execution_grant_token(build_payload(), "short")

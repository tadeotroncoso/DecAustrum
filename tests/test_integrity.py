from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.authorization_models import AuthorizationResponse
from app.integrity import (
    authorization_payload_v1,
    build_decision_integrity_proof,
    calculate_authorization_payload_hash,
)
from app.integrity_models import DecisionIntegrityProof


def build_authorization(
    *,
    context: dict | None = None,
) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision_id=uuid4(),
        project_id=uuid4(),
        evaluated_at=datetime(
            2026,
            8,
            29,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        decision="ALLOW",
        policy=None,
        policy_version=None,
        reason="No policy required approval or denial.",
        evidence=None,
        trace=[],
        agent="support-agent",
        action="read_ticket",
        context=context or {"ticket_id": 42},
    )


def test_payload_hash_uses_canonical_json():
    first = build_authorization(
        context={
            "ticket_id": 42,
            "metadata": {
                "priority": "high",
                "customer": "acme",
            },
        }
    )
    second = first.model_copy(
        update={
            "context": {
                "metadata": {
                    "customer": "acme",
                    "priority": "high",
                },
                "ticket_id": 42,
            }
        }
    )

    assert (
        calculate_authorization_payload_hash(first)
        == calculate_authorization_payload_hash(second)
    )


def test_payload_hash_changes_when_decision_payload_changes():
    authorization = build_authorization()
    changed = authorization.model_copy(
        update={"context": {"ticket_id": 43}}
    )

    assert (
        calculate_authorization_payload_hash(authorization)
        != calculate_authorization_payload_hash(changed)
    )


def test_payload_schema_v1_contains_only_frozen_contract_fields():
    authorization = build_authorization()

    assert set(authorization_payload_v1(authorization)) == {
        "decision_id",
        "project_id",
        "evaluated_at",
        "decision",
        "policy",
        "policy_version",
        "reason",
        "evidence",
        "agent",
        "action",
        "context",
        "trace",
    }

def test_integrity_proofs_form_deterministic_chain():
    first_authorization = build_authorization()
    second_authorization = build_authorization()

    first_proof = build_decision_integrity_proof(
        authorization=first_authorization,
        sequence_number=1,
        previous_hash=None,
    )
    repeated_first_proof = build_decision_integrity_proof(
        authorization=first_authorization,
        sequence_number=1,
        previous_hash=None,
    )
    second_proof = build_decision_integrity_proof(
        authorization=second_authorization,
        sequence_number=2,
        previous_hash=first_proof.record_hash,
    )

    assert first_proof == repeated_first_proof
    assert first_proof.schema_version == 1
    assert first_proof.previous_hash is None
    assert second_proof.previous_hash == first_proof.record_hash
    assert second_proof.record_hash != first_proof.record_hash
    assert len(first_proof.payload_hash) == 64
    assert len(first_proof.record_hash) == 64


def test_integrity_model_rejects_invalid_sha256_digest():
    authorization = build_authorization()

    with pytest.raises(ValidationError):
        DecisionIntegrityProof(
            decision_id=authorization.decision_id,
            project_id=authorization.project_id,
            sequence_number=1,
            payload_hash="not-a-digest",
            record_hash="0" * 64,
            created_at=authorization.evaluated_at,
        )

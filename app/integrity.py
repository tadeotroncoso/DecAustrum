import hashlib
import json
from typing import Any

from app.authorization_models import AuthorizationResponse
from app.integrity_models import DecisionIntegrityProof


INTEGRITY_ALGORITHM = "SHA-256"
INTEGRITY_SCHEMA_VERSION = 1


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_digest(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def authorization_payload_v1(
    authorization: AuthorizationResponse,
) -> dict[str, Any]:
    serialized = authorization.model_dump(mode="json")

    evidence = None

    if authorization.evidence is not None:
        evidence_data = authorization.evidence.model_dump(
            mode="json"
        )
        evidence = {
            "match": evidence_data["match"],
            "conditions": [
                {
                    "field": condition["field"],
                    "operator": condition["operator"],
                    "actual_value": condition["actual_value"],
                    "expected_value": condition[
                        "expected_value"
                    ],
                    "matched": condition["matched"],
                }
                for condition in evidence_data["conditions"]
            ],
        }

    trace = []

    for entry in authorization.trace:
        entry_data = entry.model_dump(mode="json")
        entry_evidence = entry_data["evidence"]
        trace.append(
            {
                "policy_id": entry_data["policy_id"],
                "policy_version": entry_data[
                    "policy_version"
                ],
                "decision": entry_data["decision"],
                "reason": entry_data["reason"],
                "matched": entry_data["matched"],
                "evidence": {
                    "match": entry_evidence["match"],
                    "conditions": [
                        {
                            "field": condition["field"],
                            "operator": condition["operator"],
                            "actual_value": condition[
                                "actual_value"
                            ],
                            "expected_value": condition[
                                "expected_value"
                            ],
                            "matched": condition["matched"],
                        }
                        for condition in entry_evidence[
                            "conditions"
                        ]
                    ],
                },
            }
        )

    return {
        "decision_id": serialized["decision_id"],
        "project_id": serialized["project_id"],
        "evaluated_at": serialized["evaluated_at"],
        "decision": serialized["decision"],
        "policy": serialized["policy"],
        "policy_version": serialized["policy_version"],
        "reason": serialized["reason"],
        "evidence": evidence,
        "agent": serialized["agent"],
        "action": serialized["action"],
        "context": serialized["context"],
        "trace": trace,
    }


def calculate_authorization_payload_hash(
    authorization: AuthorizationResponse,
) -> str:
    return sha256_digest(
        canonical_json(
            authorization_payload_v1(authorization)
        )
    )


def calculate_integrity_record_hash(
    *,
    authorization: AuthorizationResponse,
    sequence_number: int,
    previous_hash: str | None,
    payload_hash: str,
) -> str:
    evaluated_at = authorization_payload_v1(
        authorization
    )["evaluated_at"]
    envelope = integrity_record_envelope(
        algorithm=INTEGRITY_ALGORITHM,
        created_at=evaluated_at,
        decision_id=authorization.decision_id,
        payload_hash=payload_hash,
        previous_hash=previous_hash,
        project_id=authorization.project_id,
        schema_version=INTEGRITY_SCHEMA_VERSION,
        sequence_number=sequence_number,
    )

    return sha256_digest(canonical_json(envelope))


def integrity_record_envelope(
    *,
    algorithm: str,
    created_at: str,
    decision_id: object,
    payload_hash: str,
    previous_hash: str | None,
    project_id: object,
    schema_version: int,
    sequence_number: int,
) -> dict[str, Any]:
    return {
        "algorithm": algorithm,
        "created_at": created_at,
        "decision_id": str(decision_id),
        "payload_hash": payload_hash,
        "previous_hash": previous_hash,
        "project_id": str(project_id),
        "schema_version": schema_version,
        "sequence_number": sequence_number,
    }


def calculate_integrity_proof_record_hash(
    proof: DecisionIntegrityProof,
) -> str:
    serialized = proof.model_dump(mode="json")
    envelope = integrity_record_envelope(
        algorithm=proof.algorithm,
        created_at=serialized["created_at"],
        decision_id=proof.decision_id,
        payload_hash=proof.payload_hash,
        previous_hash=proof.previous_hash,
        project_id=proof.project_id,
        schema_version=proof.schema_version,
        sequence_number=proof.sequence_number,
    )

    return sha256_digest(canonical_json(envelope))


def build_decision_integrity_proof(
    *,
    authorization: AuthorizationResponse,
    sequence_number: int,
    previous_hash: str | None,
) -> DecisionIntegrityProof:
    payload_hash = calculate_authorization_payload_hash(
        authorization
    )
    record_hash = calculate_integrity_record_hash(
        authorization=authorization,
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        payload_hash=payload_hash,
    )

    return DecisionIntegrityProof(
        decision_id=authorization.decision_id,
        project_id=authorization.project_id,
        sequence_number=sequence_number,
        previous_hash=previous_hash,
        payload_hash=payload_hash,
        record_hash=record_hash,
        schema_version=INTEGRITY_SCHEMA_VERSION,
        created_at=authorization.evaluated_at,
    )

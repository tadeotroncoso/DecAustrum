from uuid import UUID

from fastapi import HTTPException

from app.evidence_store import EvidenceStore
from app.integrity_models import (
    DecisionIntegrityProof,
    VerifiableDecisionRecord,
)


def get_decision_integrity_or_404(
    *,
    decision_id: UUID,
    project_id: UUID,
    store: EvidenceStore,
) -> DecisionIntegrityProof:
    proof = store.get_decision_integrity(
        decision_id=decision_id,
        project_id=project_id,
    )

    if proof is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "decision_integrity_not_found",
                "message": (
                    f"Integrity proof for decision "
                    f"'{decision_id}' was not found."
                ),
            },
        )

    return proof


def get_verifiable_decision_or_404(
    *,
    decision_id: UUID,
    project_id: UUID,
    store: EvidenceStore,
) -> VerifiableDecisionRecord:
    decision = store.get(
        decision_id=decision_id,
        project_id=project_id,
    )

    if decision is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "decision_not_found",
                "message": (
                    f"Decision '{decision_id}' was not found."
                ),
            },
        )

    integrity = get_decision_integrity_or_404(
        decision_id=decision_id,
        project_id=project_id,
        store=store,
    )

    return VerifiableDecisionRecord(
        decision=decision,
        integrity=integrity,
    )

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException

from app.evidence import (
    build_evidence_bundle,
    build_evidence_bundle_archive,
    verify_evidence_bundle,
)
from app.evidence_models import (
    DecisionSearchFilters,
    EvidenceBundle,
    EvidenceExportSnapshot,
)
from app.evidence_store import EvidenceStore
from app.exceptions import EvidenceExportSizeLimitError
from app.integrity_models import VerifiableDecisionRecord

MAX_EVIDENCE_EXPORT_RECORDS = 2_000
MAX_EVIDENCE_EXPORT_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_BUNDLE_CHAIN_RECORDS = 10_000
MAX_EVIDENCE_BUNDLE_CHAIN_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_BUNDLE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class PreparedEvidenceExport:
    filters: DecisionSearchFilters
    snapshot: EvidenceExportSnapshot
    records: tuple[VerifiableDecisionRecord, ...]


def _integrity_conflict(
    verification,
) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={
            "code": "evidence_integrity_verification_failed",
            "message": (
                "Evidence cannot be exported because the decision "
                "ledger did not pass integrity verification."
            ),
            "verification": verification.model_dump(mode="json"),
        },
    )


def _size_limit_response(
    error: EvidenceExportSizeLimitError,
) -> HTTPException:
    code = {
        "bundle": "evidence_bundle_too_large",
        "chain": "evidence_chain_too_large",
        "records": "evidence_export_too_large",
    }.get(error.scope, "evidence_export_too_large")
    message = {
        "bundle": "The generated evidence bundle exceeds its byte limit.",
        "chain": (
            "The integrity chain exceeds the generated evidence byte limit."
        ),
        "records": "The selected evidence exceeds the export byte limit.",
    }.get(error.scope, "The generated evidence exceeds its byte limit.")
    return HTTPException(
        status_code=413,
        detail={
            "code": code,
            "message": message,
            "maximum_bytes": error.maximum_bytes,
        },
    )


def prepare_evidence_export(
    *,
    project_id: UUID,
    filters: DecisionSearchFilters,
    store: EvidenceStore,
    expected_head_hash: str | None = None,
    include_chain: bool = False,
) -> PreparedEvidenceExport:
    try:
        snapshot, records = store.capture_evidence_export_records(
            project_id=project_id,
            filters=filters,
            maximum_records=MAX_EVIDENCE_EXPORT_RECORDS,
            maximum_bytes=MAX_EVIDENCE_EXPORT_BYTES,
        )
    except EvidenceExportSizeLimitError as exc:
        raise _size_limit_response(exc) from exc

    if snapshot.record_count > MAX_EVIDENCE_EXPORT_RECORDS:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "evidence_export_too_large",
                "message": (
                    "The search selects too many records for one "
                    "export. Narrow the filters and try again."
                ),
                "record_count": snapshot.record_count,
                "maximum": MAX_EVIDENCE_EXPORT_RECORDS,
            },
        )

    if (
        include_chain
        and snapshot.chain_record_count
        > MAX_EVIDENCE_BUNDLE_CHAIN_RECORDS
    ):
        raise HTTPException(
            status_code=413,
            detail={
                "code": "evidence_chain_too_large",
                "message": (
                    "The integrity chain is too large for one bundle."
                ),
                "chain_record_count": snapshot.chain_record_count,
                "maximum": MAX_EVIDENCE_BUNDLE_CHAIN_RECORDS,
            },
        )

    snapshot_verification = store.verify_decision_integrity(
        project_id=project_id,
        expected_head_hash=snapshot.chain_head_hash,
    )

    if not snapshot_verification.verified:
        raise _integrity_conflict(snapshot_verification)

    if (
        expected_head_hash is not None
        and expected_head_hash != snapshot.chain_head_hash
    ):
        checkpoint_verification = store.verify_decision_integrity(
            project_id=project_id,
            expected_head_hash=expected_head_hash,
        )

        if not checkpoint_verification.verified:
            raise _integrity_conflict(checkpoint_verification)

    return PreparedEvidenceExport(
        filters=filters,
        snapshot=snapshot,
        records=tuple(records),
    )


def create_evidence_bundle(
    *,
    prepared: PreparedEvidenceExport,
    store: EvidenceStore,
    expected_head_hash: str | None = None,
) -> EvidenceBundle:
    snapshot = prepared.snapshot
    records = list(prepared.records)
    try:
        chain = store.list_evidence_chain(
            project_id=snapshot.project_id,
            max_sequence_number=snapshot.max_sequence_number,
            maximum_bytes=MAX_EVIDENCE_BUNDLE_CHAIN_BYTES,
        )
    except EvidenceExportSizeLimitError as exc:
        raise _size_limit_response(exc) from exc
    bundle = build_evidence_bundle(
        snapshot=snapshot,
        criteria=prepared.filters,
        records=records,
        chain=chain,
        expected_head_hash=expected_head_hash,
        generated_at=datetime.now(timezone.utc),
    )
    verification = verify_evidence_bundle(
        bundle,
        expected_head_hash=expected_head_hash,
    )

    if not verification.verified:
        raise RuntimeError(
            "DecAustrum generated an evidence bundle that failed "
            f"verification: {verification.failure}"
        )

    return bundle


def create_evidence_bundle_archive(
    *,
    prepared: PreparedEvidenceExport,
    store: EvidenceStore,
    expected_head_hash: str | None = None,
) -> tuple[EvidenceBundle, bytes]:
    bundle = create_evidence_bundle(
        prepared=prepared,
        store=store,
        expected_head_hash=expected_head_hash,
    )

    try:
        archive = build_evidence_bundle_archive(
            bundle,
            maximum_bytes=MAX_EVIDENCE_BUNDLE_BYTES,
        )
    except EvidenceExportSizeLimitError as exc:
        raise _size_limit_response(exc) from exc

    return bundle, archive


def evidence_response_headers(
    snapshot: EvidenceExportSnapshot,
) -> dict[str, str]:
    return {
        "X-DecAustrum-Project-ID": str(snapshot.project_id),
        "X-DecAustrum-Snapshot-At": (
            snapshot.captured_at.isoformat()
        ),
        "X-DecAustrum-Record-Count": str(snapshot.record_count),
        "X-DecAustrum-Max-Sequence": str(
            snapshot.max_sequence_number
        ),
        "X-DecAustrum-Chain-Head": (
            snapshot.chain_head_hash or ""
        ),
    }


__all__ = [
    "MAX_EVIDENCE_BUNDLE_CHAIN_RECORDS",
    "MAX_EVIDENCE_BUNDLE_BYTES",
    "MAX_EVIDENCE_BUNDLE_CHAIN_BYTES",
    "MAX_EVIDENCE_EXPORT_BYTES",
    "MAX_EVIDENCE_EXPORT_RECORDS",
    "PreparedEvidenceExport",
    "create_evidence_bundle",
    "create_evidence_bundle_archive",
    "evidence_response_headers",
    "prepare_evidence_export",
]

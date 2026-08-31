import csv
import io
import json
import zipfile
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import ValidationError

from app.evidence_models import (
    DecisionSearchFilters,
    EvidenceBundle,
    EvidenceBundleManifest,
    EvidenceBundleVerification,
    EvidenceBundleVerificationFailure,
    EvidenceExportSnapshot,
)
from app.integrity import (
    calculate_authorization_payload_hash,
    calculate_integrity_proof_record_hash,
    canonical_json,
    sha256_digest,
)
from app.integrity_models import (
    DecisionIntegrityProof,
    VerifiableDecisionRecord,
)

EVIDENCE_BUNDLE_FILES = {
    "manifest.json",
    "records.ndjson",
    "chain.ndjson",
}
MAX_EVIDENCE_ARCHIVE_BYTES = 200 * 1024 * 1024

CSV_COLUMNS = (
    "decision_id",
    "project_id",
    "evaluated_at",
    "decision",
    "policy_id",
    "policy_version",
    "reason",
    "agent",
    "action",
    "context_json",
    "evidence_json",
    "trace_json",
    "sequence_number",
    "previous_hash",
    "payload_hash",
    "record_hash",
    "algorithm",
    "integrity_schema_version",
    "integrity_created_at",
)


class EvidenceBundleArchiveError(ValueError):
    """Raised when an evidence ZIP cannot be safely reconstructed."""


def _model_data(value: Any) -> Any:
    return value.model_dump(mode="json")


def _models_data(values: Iterable[Any]) -> list[Any]:
    return [_model_data(value) for value in values]


def _logical_bundle_payload(
    *,
    manifest_data: dict[str, Any],
    records_data: list[dict[str, Any]],
    chain_data: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "manifest": manifest_data,
        "records": records_data,
        "chain": chain_data,
    }


def _manifest_without_bundle_digest(
    manifest: EvidenceBundleManifest,
) -> dict[str, Any]:
    return manifest.model_dump(
        mode="json",
        exclude={"bundle_sha256"},
    )


def build_evidence_bundle(
    *,
    snapshot: EvidenceExportSnapshot,
    criteria: DecisionSearchFilters,
    records: list[VerifiableDecisionRecord],
    chain: list[DecisionIntegrityProof],
    expected_head_hash: str | None = None,
    generated_at: datetime | None = None,
    export_id: UUID | None = None,
) -> EvidenceBundle:
    if len(records) != snapshot.record_count:
        raise ValueError(
            "Export record count changed after the snapshot was created."
        )

    if len(chain) != snapshot.chain_record_count:
        raise ValueError(
            "Integrity chain changed after the snapshot was created."
        )

    actual_head_hash = chain[-1].record_hash if chain else None

    if actual_head_hash != snapshot.chain_head_hash:
        raise ValueError(
            "Integrity chain head changed after the snapshot was created."
        )

    records_data = _models_data(records)
    chain_data = _models_data(chain)
    records_digest = sha256_digest(canonical_json(records_data))
    chain_digest = sha256_digest(canonical_json(chain_data))
    manifest_data = {
        "schema_version": 1,
        "export_id": str(export_id or uuid4()),
        "generated_at": (
            generated_at or datetime.now(timezone.utc)
        ),
        "snapshot_at": snapshot.captured_at,
        "project_id": snapshot.project_id,
        "criteria": criteria,
        "record_count": snapshot.record_count,
        "chain_record_count": snapshot.chain_record_count,
        "chain_head_hash": snapshot.chain_head_hash,
        "expected_head_hash": expected_head_hash,
        "records_sha256": records_digest,
        "chain_sha256": chain_digest,
    }
    serialized_manifest_data = (
        EvidenceBundleManifest.model_validate(
            {
                **manifest_data,
                "bundle_sha256": "0" * 64,
            }
        ).model_dump(
            mode="json",
            exclude={"bundle_sha256"},
        )
    )
    bundle_digest = sha256_digest(
        canonical_json(
            _logical_bundle_payload(
                manifest_data=serialized_manifest_data,
                records_data=records_data,
                chain_data=chain_data,
            )
        )
    )
    manifest = EvidenceBundleManifest.model_validate(
        {
            **manifest_data,
            "bundle_sha256": bundle_digest,
        }
    )

    return EvidenceBundle(
        manifest=manifest,
        records=records,
        chain=chain,
    )


def _failed_verification(
    *,
    bundle: EvidenceBundle,
    failure: EvidenceBundleVerificationFailure,
    checked_records: int = 0,
    checked_chain_records: int = 0,
) -> EvidenceBundleVerification:
    return EvidenceBundleVerification(
        verified=False,
        project_id=bundle.manifest.project_id,
        checked_records=checked_records,
        checked_chain_records=checked_chain_records,
        head_hash=(
            bundle.chain[-1].record_hash
            if bundle.chain
            else None
        ),
        verified_at=datetime.now(timezone.utc),
        failure=failure,
    )


def verify_evidence_bundle(
    bundle: EvidenceBundle,
    *,
    expected_head_hash: str | None = None,
) -> EvidenceBundleVerification:
    manifest = bundle.manifest
    records_data = _models_data(bundle.records)
    chain_data = _models_data(bundle.chain)

    if manifest.record_count != len(bundle.records):
        return _failed_verification(
            bundle=bundle,
            failure=EvidenceBundleVerificationFailure(
                code="manifest_record_count_mismatch",
                message="Manifest and exported record counts do not match.",
                expected=str(manifest.record_count),
                actual=str(len(bundle.records)),
            ),
        )

    if manifest.chain_record_count != len(bundle.chain):
        return _failed_verification(
            bundle=bundle,
            failure=EvidenceBundleVerificationFailure(
                code="manifest_chain_count_mismatch",
                message="Manifest and integrity chain counts do not match.",
                expected=str(manifest.chain_record_count),
                actual=str(len(bundle.chain)),
            ),
        )

    actual_records_digest = sha256_digest(
        canonical_json(records_data)
    )

    if manifest.records_sha256 != actual_records_digest:
        return _failed_verification(
            bundle=bundle,
            failure=EvidenceBundleVerificationFailure(
                code="records_digest_mismatch",
                message="Exported decision records were modified.",
                expected=manifest.records_sha256,
                actual=actual_records_digest,
            ),
        )

    actual_chain_digest = sha256_digest(canonical_json(chain_data))

    if manifest.chain_sha256 != actual_chain_digest:
        return _failed_verification(
            bundle=bundle,
            failure=EvidenceBundleVerificationFailure(
                code="chain_digest_mismatch",
                message="Exported integrity chain records were modified.",
                expected=manifest.chain_sha256,
                actual=actual_chain_digest,
            ),
        )

    actual_bundle_digest = sha256_digest(
        canonical_json(
            _logical_bundle_payload(
                manifest_data=_manifest_without_bundle_digest(
                    manifest
                ),
                records_data=records_data,
                chain_data=chain_data,
            )
        )
    )

    if manifest.bundle_sha256 != actual_bundle_digest:
        return _failed_verification(
            bundle=bundle,
            failure=EvidenceBundleVerificationFailure(
                code="bundle_digest_mismatch",
                message="Evidence bundle manifest was modified.",
                expected=manifest.bundle_sha256,
                actual=actual_bundle_digest,
            ),
        )

    previous_hash = None
    proofs_by_decision_id: dict[UUID, DecisionIntegrityProof] = {}

    for expected_sequence, proof in enumerate(bundle.chain, start=1):
        if proof.project_id != manifest.project_id:
            return _failed_verification(
                bundle=bundle,
                checked_chain_records=expected_sequence - 1,
                failure=EvidenceBundleVerificationFailure(
                    code="project_mismatch",
                    message=(
                        "Integrity record belongs to another project."
                    ),
                    decision_id=proof.decision_id,
                    sequence_number=proof.sequence_number,
                    expected=str(manifest.project_id),
                    actual=str(proof.project_id),
                ),
            )

        if proof.sequence_number != expected_sequence:
            return _failed_verification(
                bundle=bundle,
                checked_chain_records=expected_sequence - 1,
                failure=EvidenceBundleVerificationFailure(
                    code="chain_sequence_mismatch",
                    message="Integrity chain sequence is not contiguous.",
                    decision_id=proof.decision_id,
                    sequence_number=expected_sequence,
                    expected=str(expected_sequence),
                    actual=str(proof.sequence_number),
                ),
            )

        if proof.previous_hash != previous_hash:
            return _failed_verification(
                bundle=bundle,
                checked_chain_records=expected_sequence - 1,
                failure=EvidenceBundleVerificationFailure(
                    code="chain_previous_hash_mismatch",
                    message=(
                        "Integrity record does not reference its "
                        "predecessor."
                    ),
                    decision_id=proof.decision_id,
                    sequence_number=proof.sequence_number,
                    expected=previous_hash,
                    actual=proof.previous_hash,
                ),
            )

        calculated_record_hash = (
            calculate_integrity_proof_record_hash(proof)
        )

        if proof.record_hash != calculated_record_hash:
            return _failed_verification(
                bundle=bundle,
                checked_chain_records=expected_sequence - 1,
                failure=EvidenceBundleVerificationFailure(
                    code="chain_record_hash_mismatch",
                    message="Integrity record hash is invalid.",
                    decision_id=proof.decision_id,
                    sequence_number=proof.sequence_number,
                    expected=proof.record_hash,
                    actual=calculated_record_hash,
                ),
            )

        if proof.decision_id in proofs_by_decision_id:
            return _failed_verification(
                bundle=bundle,
                checked_chain_records=expected_sequence - 1,
                failure=EvidenceBundleVerificationFailure(
                    code="chain_sequence_mismatch",
                    message=(
                        "Integrity chain contains a duplicate decision."
                    ),
                    decision_id=proof.decision_id,
                    sequence_number=proof.sequence_number,
                ),
            )

        proofs_by_decision_id[proof.decision_id] = proof
        previous_hash = proof.record_hash

    actual_head_hash = previous_hash

    if manifest.chain_head_hash != actual_head_hash:
        return _failed_verification(
            bundle=bundle,
            checked_chain_records=len(bundle.chain),
            failure=EvidenceBundleVerificationFailure(
                code="chain_head_mismatch",
                message="Manifest chain head does not match the chain.",
                expected=manifest.chain_head_hash,
                actual=actual_head_hash,
            ),
        )

    chain_hashes = {proof.record_hash for proof in bundle.chain}

    for checkpoint in (
        manifest.expected_head_hash,
        expected_head_hash,
    ):
        if checkpoint is not None and checkpoint not in chain_hashes:
            return _failed_verification(
                bundle=bundle,
                checked_chain_records=len(bundle.chain),
                failure=EvidenceBundleVerificationFailure(
                    code="trusted_checkpoint_mismatch",
                    message=(
                        "Trusted checkpoint is not present in the "
                        "exported integrity chain."
                    ),
                    expected=checkpoint,
                    actual=actual_head_hash,
                ),
            )

    checked_records = 0
    selected_decision_ids: set[UUID] = set()

    for record in bundle.records:
        decision = record.decision
        proof = record.integrity

        if (
            decision.project_id != manifest.project_id
            or proof.project_id != manifest.project_id
        ):
            return _failed_verification(
                bundle=bundle,
                checked_records=checked_records,
                checked_chain_records=len(bundle.chain),
                failure=EvidenceBundleVerificationFailure(
                    code="project_mismatch",
                    message=(
                        "Selected decision belongs to another project."
                    ),
                    decision_id=decision.decision_id,
                    expected=str(manifest.project_id),
                    actual=str(decision.project_id),
                ),
            )

        chain_proof = proofs_by_decision_id.get(decision.decision_id)

        if chain_proof is None:
            return _failed_verification(
                bundle=bundle,
                checked_records=checked_records,
                checked_chain_records=len(bundle.chain),
                failure=EvidenceBundleVerificationFailure(
                    code="selected_record_missing",
                    message=(
                        "Selected decision is missing from the chain."
                    ),
                    decision_id=decision.decision_id,
                ),
            )

        if (
            proof.decision_id != decision.decision_id
            or proof != chain_proof
            or decision.decision_id in selected_decision_ids
        ):
            return _failed_verification(
                bundle=bundle,
                checked_records=checked_records,
                checked_chain_records=len(bundle.chain),
                failure=EvidenceBundleVerificationFailure(
                    code="selected_proof_mismatch",
                    message=(
                        "Selected decision and its integrity proof do "
                        "not match the chain."
                    ),
                    decision_id=decision.decision_id,
                    sequence_number=proof.sequence_number,
                ),
            )

        calculated_payload_hash = (
            calculate_authorization_payload_hash(decision)
        )

        if proof.payload_hash != calculated_payload_hash:
            return _failed_verification(
                bundle=bundle,
                checked_records=checked_records,
                checked_chain_records=len(bundle.chain),
                failure=EvidenceBundleVerificationFailure(
                    code="selected_payload_hash_mismatch",
                    message="Selected decision payload was modified.",
                    decision_id=decision.decision_id,
                    sequence_number=proof.sequence_number,
                    expected=proof.payload_hash,
                    actual=calculated_payload_hash,
                ),
            )

        selected_decision_ids.add(decision.decision_id)
        checked_records += 1

    return EvidenceBundleVerification(
        verified=True,
        project_id=manifest.project_id,
        checked_records=checked_records,
        checked_chain_records=len(bundle.chain),
        head_hash=actual_head_hash,
        verified_at=datetime.now(timezone.utc),
        failure=None,
    )


def iter_json_export(
    *,
    snapshot: EvidenceExportSnapshot,
    criteria: DecisionSearchFilters,
    records: Iterable[VerifiableDecisionRecord],
) -> Iterator[bytes]:
    metadata = {
        "schema_version": 1,
        "project_id": snapshot.project_id,
        "criteria": criteria,
        "snapshot": snapshot,
    }
    prefix = canonical_json(
        {
            key: (
                value.model_dump(mode="json")
                if hasattr(value, "model_dump")
                else str(value) if isinstance(value, UUID) else value
            )
            for key, value in metadata.items()
        }
    )
    yield (prefix[:-1] + ',"records":[').encode("utf-8")
    first = True

    for record in records:
        if not first:
            yield b","

        yield canonical_json(_model_data(record)).encode("utf-8")
        first = False

    yield b"]}"


def iter_ndjson_export(
    records: Iterable[VerifiableDecisionRecord],
) -> Iterator[bytes]:
    for record in records:
        yield (
            canonical_json(_model_data(record)) + "\n"
        ).encode("utf-8")


def _csv_row(
    record: VerifiableDecisionRecord,
) -> dict[str, Any]:
    decision = record.decision.model_dump(mode="json")
    proof = record.integrity.model_dump(mode="json")

    return {
        "decision_id": decision["decision_id"],
        "project_id": decision["project_id"],
        "evaluated_at": decision["evaluated_at"],
        "decision": decision["decision"],
        "policy_id": decision["policy"],
        "policy_version": decision["policy_version"],
        "reason": decision["reason"],
        "agent": decision["agent"],
        "action": decision["action"],
        "context_json": canonical_json(decision["context"]),
        "evidence_json": (
            canonical_json(decision["evidence"])
            if decision["evidence"] is not None
            else ""
        ),
        "trace_json": canonical_json(decision["trace"]),
        "sequence_number": proof["sequence_number"],
        "previous_hash": proof["previous_hash"],
        "payload_hash": proof["payload_hash"],
        "record_hash": proof["record_hash"],
        "algorithm": proof["algorithm"],
        "integrity_schema_version": proof["schema_version"],
        "integrity_created_at": proof["created_at"],
    }


def iter_csv_export(
    records: Iterable[VerifiableDecisionRecord],
) -> Iterator[bytes]:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=CSV_COLUMNS,
        lineterminator="\n",
    )
    writer.writeheader()
    yield buffer.getvalue().encode("utf-8")

    for record in records:
        buffer.seek(0)
        buffer.truncate(0)
        writer.writerow(_csv_row(record))
        yield buffer.getvalue().encode("utf-8")


def _write_deterministic_zip_member(
    archive: zipfile.ZipFile,
    name: str,
    content: str,
) -> None:
    info = zipfile.ZipInfo(
        filename=name,
        date_time=(1980, 1, 1, 0, 0, 0),
    )
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    archive.writestr(info, content.encode("utf-8"))


def build_evidence_bundle_archive(
    bundle: EvidenceBundle,
) -> bytes:
    output = io.BytesIO()

    with zipfile.ZipFile(output, mode="w") as archive:
        _write_deterministic_zip_member(
            archive,
            "manifest.json",
            canonical_json(bundle.manifest.model_dump(mode="json"))
            + "\n",
        )
        _write_deterministic_zip_member(
            archive,
            "records.ndjson",
            "".join(
                canonical_json(record.model_dump(mode="json"))
                + "\n"
                for record in bundle.records
            ),
        )
        _write_deterministic_zip_member(
            archive,
            "chain.ndjson",
            "".join(
                canonical_json(proof.model_dump(mode="json"))
                + "\n"
                for proof in bundle.chain
            ),
        )

    return output.getvalue()


def _read_archive_bytes(source: bytes | Path | str) -> bytes:
    if isinstance(source, bytes):
        if len(source) > MAX_EVIDENCE_ARCHIVE_BYTES:
            raise EvidenceBundleArchiveError(
                "Evidence archive exceeds the verification size limit."
            )

        return source

    path = Path(source)

    if path.stat().st_size > MAX_EVIDENCE_ARCHIVE_BYTES:
        raise EvidenceBundleArchiveError(
            "Evidence archive exceeds the verification size limit."
        )

    return path.read_bytes()


def _parse_ndjson(
    content: bytes,
    *,
    filename: str,
) -> list[Any]:
    values = []

    for line_number, line in enumerate(
        content.decode("utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue

        try:
            values.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise EvidenceBundleArchiveError(
                f"{filename}:{line_number} is not valid JSON."
            ) from exc

    return values


def load_evidence_bundle_archive(
    source: bytes | Path | str,
) -> EvidenceBundle:
    try:
        archive_bytes = _read_archive_bytes(source)
    except OSError as exc:
        raise EvidenceBundleArchiveError(
            f"Evidence archive cannot be read: {exc}"
        ) from exc

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = archive.namelist()

            if (
                len(names) != len(set(names))
                or set(names) != EVIDENCE_BUNDLE_FILES
            ):
                raise EvidenceBundleArchiveError(
                    "Evidence archive must contain exactly manifest.json, "
                    "records.ndjson, and chain.ndjson."
                )

            total_size = sum(
                member.file_size
                for member in archive.infolist()
            )

            if total_size > MAX_EVIDENCE_ARCHIVE_BYTES:
                raise EvidenceBundleArchiveError(
                    "Evidence archive exceeds the verification size limit."
                )

            manifest_data = json.loads(
                archive.read("manifest.json").decode("utf-8")
            )
            records_data = _parse_ndjson(
                archive.read("records.ndjson"),
                filename="records.ndjson",
            )
            chain_data = _parse_ndjson(
                archive.read("chain.ndjson"),
                filename="chain.ndjson",
            )
    except EvidenceBundleArchiveError:
        raise
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        zipfile.BadZipFile,
    ) as exc:
        raise EvidenceBundleArchiveError(
            "Evidence archive is malformed."
        ) from exc

    try:
        return EvidenceBundle.model_validate(
            {
                "manifest": manifest_data,
                "records": records_data,
                "chain": chain_data,
            }
        )
    except ValidationError as exc:
        raise EvidenceBundleArchiveError(
            "Evidence archive contains invalid DecAustrum data."
        ) from exc


__all__ = [
    "CSV_COLUMNS",
    "EvidenceBundleArchiveError",
    "build_evidence_bundle",
    "build_evidence_bundle_archive",
    "iter_csv_export",
    "iter_json_export",
    "iter_ndjson_export",
    "load_evidence_bundle_archive",
    "verify_evidence_bundle",
]

import csv
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from app.authorization_models import AuthorizationResponse
from app.evidence import (
    EvidenceBundleArchiveError,
    build_evidence_bundle,
    build_evidence_bundle_archive,
    iter_csv_export,
    iter_json_export,
    iter_ndjson_export,
    load_evidence_bundle_archive,
    verify_evidence_bundle,
)
from app.evidence_models import (
    DecisionSearchFilters,
    EvidenceExportSnapshot,
)
from app.integrity import (
    build_decision_integrity_proof,
    canonical_json,
    sha256_digest,
)
from app.integrity_models import VerifiableDecisionRecord

PROJECT_ID = UUID("10000000-0000-0000-0000-000000000001")
BASE_TIME = datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc)


def build_authorization(index: int) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision_id=UUID(
            f"20000000-0000-0000-0000-{index:012d}"
        ),
        project_id=PROJECT_ID,
        evaluated_at=BASE_TIME + timedelta(minutes=index),
        decision="ALLOW",
        policy=None,
        policy_version=None,
        reason="No policy required approval or denial.",
        evidence=None,
        agent=f"support-agent-{index}",
        action="read_ticket",
        context={"ticket_id": index},
        trace=[],
    )


def build_records(
    count: int = 2,
) -> list[VerifiableDecisionRecord]:
    records = []
    previous_hash = None

    for index in range(1, count + 1):
        authorization = build_authorization(index)
        proof = build_decision_integrity_proof(
            authorization=authorization,
            sequence_number=index,
            previous_hash=previous_hash,
        )
        records.append(
            VerifiableDecisionRecord(
                decision=authorization,
                integrity=proof,
            )
        )
        previous_hash = proof.record_hash

    return records


def build_bundle(
    *,
    selected_indexes: tuple[int, ...] = (0, 1),
    expected_head_hash: str | None = None,
):
    complete_records = build_records()
    selected_records = [
        complete_records[index]
        for index in selected_indexes
    ]
    chain = [record.integrity for record in complete_records]
    snapshot = EvidenceExportSnapshot(
        project_id=PROJECT_ID,
        captured_at=BASE_TIME,
        max_sequence_number=len(chain),
        chain_record_count=len(chain),
        chain_head_hash=chain[-1].record_hash,
        record_count=len(selected_records),
    )

    return build_evidence_bundle(
        snapshot=snapshot,
        criteria=DecisionSearchFilters(action="read_ticket"),
        records=selected_records,
        chain=chain,
        expected_head_hash=expected_head_hash,
        generated_at=BASE_TIME,
        export_id=UUID(
            "30000000-0000-0000-0000-000000000001"
        ),
    )


def recompute_container_digests(bundle) -> None:
    records_data = [
        record.model_dump(mode="json")
        for record in bundle.records
    ]
    chain_data = [
        proof.model_dump(mode="json")
        for proof in bundle.chain
    ]
    bundle.manifest.records_sha256 = sha256_digest(
        canonical_json(records_data)
    )
    bundle.manifest.chain_sha256 = sha256_digest(
        canonical_json(chain_data)
    )
    manifest_data = bundle.manifest.model_dump(
        mode="json",
        exclude={"bundle_sha256"},
    )
    bundle.manifest.bundle_sha256 = sha256_digest(
        canonical_json(
            {
                "manifest": manifest_data,
                "records": records_data,
                "chain": chain_data,
            }
        )
    )

def test_bundle_round_trip_is_self_verifying_and_deterministic():
    bundle = build_bundle()

    verification = verify_evidence_bundle(bundle)
    first_archive = build_evidence_bundle_archive(bundle)
    second_archive = build_evidence_bundle_archive(bundle)
    loaded = load_evidence_bundle_archive(first_archive)

    assert verification.verified is True
    assert verification.checked_records == 2
    assert verification.checked_chain_records == 2
    assert verification.head_hash == bundle.manifest.chain_head_hash
    assert loaded == bundle
    assert verify_evidence_bundle(loaded).verified is True
    assert first_archive == second_archive

    with zipfile.ZipFile(io.BytesIO(first_archive)) as archive:
        assert set(archive.namelist()) == {
            "manifest.json",
            "records.ndjson",
            "chain.ndjson",
        }


def test_filtered_bundle_contains_full_chain_and_accepts_old_checkpoint():
    records = build_records()
    old_checkpoint = records[0].integrity.record_hash
    bundle = build_bundle(
        selected_indexes=(1,),
        expected_head_hash=old_checkpoint,
    )

    verification = verify_evidence_bundle(
        bundle,
        expected_head_hash=old_checkpoint,
    )

    assert len(bundle.records) == 1
    assert len(bundle.chain) == 2
    assert verification.verified is True


def test_verifier_detects_modified_decision_payload():
    bundle = build_bundle()
    bundle.records[0].decision.context["ticket_id"] = 999

    verification = verify_evidence_bundle(bundle)

    assert verification.verified is False
    assert verification.failure is not None
    assert verification.failure.code == "records_digest_mismatch"


def test_verifier_detects_modified_integrity_chain():
    bundle = build_bundle()
    bundle.chain[1] = bundle.chain[1].model_copy(
        update={"previous_hash": "0" * 64}
    )

    verification = verify_evidence_bundle(bundle)

    assert verification.verified is False
    assert verification.failure is not None
    assert verification.failure.code == "chain_digest_mismatch"


def test_verifier_detects_payload_tampering_after_digests_are_rebuilt():
    bundle = build_bundle()
    bundle.records[0].decision.context["ticket_id"] = 999
    recompute_container_digests(bundle)

    verification = verify_evidence_bundle(bundle)

    assert verification.verified is False
    assert verification.failure is not None
    assert verification.failure.code == (
        "selected_payload_hash_mismatch"
    )


def test_verifier_detects_broken_chain_after_digests_are_rebuilt():
    bundle = build_bundle()
    bundle.chain[1] = bundle.chain[1].model_copy(
        update={"previous_hash": "0" * 64}
    )
    recompute_container_digests(bundle)

    verification = verify_evidence_bundle(bundle)

    assert verification.verified is False
    assert verification.failure is not None
    assert verification.failure.code == (
        "chain_previous_hash_mismatch"
    )


def test_verifier_rejects_untrusted_checkpoint():
    bundle = build_bundle()

    verification = verify_evidence_bundle(
        bundle,
        expected_head_hash="0" * 64,
    )

    assert verification.verified is False
    assert verification.failure is not None
    assert verification.failure.code == "trusted_checkpoint_mismatch"


def test_empty_bundle_is_valid_without_a_checkpoint():
    snapshot = EvidenceExportSnapshot(
        project_id=PROJECT_ID,
        captured_at=BASE_TIME,
        max_sequence_number=0,
        chain_record_count=0,
        chain_head_hash=None,
        record_count=0,
    )
    bundle = build_evidence_bundle(
        snapshot=snapshot,
        criteria=DecisionSearchFilters(),
        records=[],
        chain=[],
        generated_at=BASE_TIME,
    )

    verification = verify_evidence_bundle(bundle)

    assert verification.verified is True
    assert verification.head_hash is None
    assert verification.checked_records == 0


def test_archive_loader_rejects_missing_and_unexpected_members():
    output = io.BytesIO()

    with zipfile.ZipFile(output, mode="w") as archive:
        archive.writestr("manifest.json", "{}")
        archive.writestr("unexpected.txt", "hidden")

    with pytest.raises(EvidenceBundleArchiveError):
        load_evidence_bundle_archive(output.getvalue())


def test_json_ndjson_and_csv_exports_are_machine_readable():
    records = build_records()
    snapshot = EvidenceExportSnapshot(
        project_id=PROJECT_ID,
        captured_at=BASE_TIME,
        max_sequence_number=2,
        chain_record_count=2,
        chain_head_hash=records[-1].integrity.record_hash,
        record_count=2,
    )
    filters = DecisionSearchFilters(action="read_ticket")

    json_data = json.loads(
        b"".join(
            iter_json_export(
                snapshot=snapshot,
                criteria=filters,
                records=records,
            )
        )
    )
    ndjson_data = [
        json.loads(line)
        for line in b"".join(
            iter_ndjson_export(records)
        ).splitlines()
    ]
    csv_data = list(
        csv.DictReader(
            io.StringIO(
                b"".join(
                    iter_csv_export(records)
                ).decode("utf-8")
            )
        )
    )

    assert json_data["snapshot"]["record_count"] == 2
    assert json_data["criteria"]["action"] == "read_ticket"
    assert len(json_data["records"]) == 2
    assert len(ndjson_data) == 2
    assert ndjson_data[0]["integrity"]["sequence_number"] == 1
    assert len(csv_data) == 2
    assert csv_data[0]["action"] == "read_ticket"
    assert json.loads(csv_data[0]["context_json"]) == {
        "ticket_id": 1
    }

import json
from datetime import datetime, timezone
from uuid import UUID

from app.authorization_models import AuthorizationResponse
from app.evidence import (
    build_evidence_bundle,
    build_evidence_bundle_archive,
)
from app.evidence_models import (
    DecisionSearchFilters,
    EvidenceExportSnapshot,
)
from app.evidence_verifier import main
from app.integrity import build_decision_integrity_proof
from app.integrity_models import VerifiableDecisionRecord


def archive_bytes() -> tuple[bytes, str]:
    project_id = UUID(
        "60000000-0000-0000-0000-000000000001"
    )
    authorization = AuthorizationResponse(
        decision_id=UUID(
            "70000000-0000-0000-0000-000000000001"
        ),
        project_id=project_id,
        evaluated_at=datetime(
            2026,
            8,
            29,
            14,
            0,
            tzinfo=timezone.utc,
        ),
        decision="ALLOW",
        policy=None,
        policy_version=None,
        reason="No policy matched.",
        evidence=None,
        agent="cli-agent",
        action="read_ticket",
        context={"ticket_id": 1},
        trace=[],
    )
    proof = build_decision_integrity_proof(
        authorization=authorization,
        sequence_number=1,
        previous_hash=None,
    )
    bundle = build_evidence_bundle(
        snapshot=EvidenceExportSnapshot(
            project_id=project_id,
            captured_at=authorization.evaluated_at,
            max_sequence_number=1,
            chain_record_count=1,
            chain_head_hash=proof.record_hash,
            record_count=1,
        ),
        criteria=DecisionSearchFilters(),
        records=[
            VerifiableDecisionRecord(
                decision=authorization,
                integrity=proof,
            )
        ],
        chain=[proof],
    )

    return build_evidence_bundle_archive(bundle), proof.record_hash


def test_offline_verifier_returns_zero_for_valid_bundle(
    tmp_path,
    capsys,
):
    content, head_hash = archive_bytes()
    path = tmp_path / "evidence.zip"
    path.write_bytes(content)

    exit_code = main(
        [
            str(path),
            "--expected-head-hash",
            head_hash,
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["verified"] is True
    assert output["checked_records"] == 1


def test_offline_verifier_returns_one_for_wrong_checkpoint(
    tmp_path,
    capsys,
):
    content, _ = archive_bytes()
    path = tmp_path / "evidence.zip"
    path.write_bytes(content)

    exit_code = main(
        [
            str(path),
            "--expected-head-hash",
            "0" * 64,
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["failure"]["code"] == (
        "trusted_checkpoint_mismatch"
    )


def test_offline_verifier_returns_two_for_invalid_archive(
    tmp_path,
    capsys,
):
    path = tmp_path / "not-a-bundle.zip"
    path.write_bytes(b"not a zip file")

    exit_code = main([str(path)])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert output["verified"] is False
    assert output["failure"]["code"] == "archive_invalid"

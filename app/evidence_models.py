from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from app.approval_models import ApprovalStatus
from app.integrity_models import (
    DecisionIntegrityProof,
    Sha256Digest,
    VerifiableDecisionRecord,
)
from app.policy_types import Decision

DecisionSortOrder = Literal["asc", "desc"]
EvidenceExportFormat = Literal["json", "ndjson", "csv"]
EvidenceApprovalStatus = ApprovalStatus | Literal["NONE"]

SearchText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=200,
    ),
]

ExactSearchValue = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=200,
    ),
]


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone.")

    return value.astimezone(timezone.utc)


class DecisionSearchFilters(BaseModel):
    decision: Decision | None = None
    agent: ExactSearchValue | None = None
    action: ExactSearchValue | None = None
    policy_id: ExactSearchValue | None = None
    has_policy: bool | None = None
    approval_status: EvidenceApprovalStatus | None = None
    evaluated_after: datetime | None = None
    evaluated_before: datetime | None = None
    query: SearchText | None = None
    sort: DecisionSortOrder = "desc"

    @field_validator("evaluated_after", "evaluated_before")
    @classmethod
    def require_timestamp_timezone(
        cls,
        value: datetime | None,
        info,
    ) -> datetime | None:
        if value is None:
            return None

        return _utc(value, info.field_name)

    @model_validator(mode="after")
    def validate_filter_combination(self):
        if (
            self.policy_id is not None
            and self.has_policy is False
        ):
            raise ValueError(
                "policy_id cannot be combined with has_policy=false."
            )

        if (
            self.evaluated_after is not None
            and self.evaluated_before is not None
            and self.evaluated_after > self.evaluated_before
        ):
            raise ValueError(
                "evaluated_after must be earlier than or equal "
                "to evaluated_before."
            )

        return self


class EvidenceExportSnapshot(BaseModel):
    project_id: UUID
    captured_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    max_sequence_number: int = Field(ge=0)
    chain_record_count: int = Field(ge=0)
    chain_head_hash: Sha256Digest | None = None
    record_count: int = Field(ge=0)

    @field_validator("captured_at")
    @classmethod
    def require_captured_at_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        return _utc(value, "captured_at")


class EvidenceBundleManifest(BaseModel):
    schema_version: Literal[1] = 1
    export_id: UUID
    generated_at: datetime
    snapshot_at: datetime
    project_id: UUID
    criteria: DecisionSearchFilters
    record_count: int = Field(ge=0)
    chain_record_count: int = Field(ge=0)
    chain_head_hash: Sha256Digest | None = None
    expected_head_hash: Sha256Digest | None = None
    records_sha256: Sha256Digest
    chain_sha256: Sha256Digest
    bundle_sha256: Sha256Digest

    @field_validator("generated_at", "snapshot_at")
    @classmethod
    def require_generated_at_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        return _utc(value, "bundle timestamp")


class EvidenceBundle(BaseModel):
    manifest: EvidenceBundleManifest
    records: list[VerifiableDecisionRecord]
    chain: list[DecisionIntegrityProof]


EvidenceBundleFailureCode = Literal[
    "manifest_record_count_mismatch",
    "manifest_chain_count_mismatch",
    "records_digest_mismatch",
    "chain_digest_mismatch",
    "bundle_digest_mismatch",
    "project_mismatch",
    "chain_sequence_mismatch",
    "chain_previous_hash_mismatch",
    "chain_record_hash_mismatch",
    "chain_head_mismatch",
    "trusted_checkpoint_mismatch",
    "selected_record_missing",
    "selected_proof_mismatch",
    "selected_payload_hash_mismatch",
]


class EvidenceBundleVerificationFailure(BaseModel):
    code: EvidenceBundleFailureCode
    message: str
    decision_id: UUID | None = None
    sequence_number: int | None = Field(default=None, ge=1)
    expected: str | None = None
    actual: str | None = None


class EvidenceBundleVerification(BaseModel):
    verified: bool
    project_id: UUID
    checked_records: int = Field(ge=0)
    checked_chain_records: int = Field(ge=0)
    head_hash: Sha256Digest | None = None
    verified_at: datetime
    failure: EvidenceBundleVerificationFailure | None = None

    @field_validator("verified_at")
    @classmethod
    def require_verified_at_timezone(
        cls,
        value: datetime,
    ) -> datetime:
        return _utc(value, "verified_at")

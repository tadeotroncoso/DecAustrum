from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field, StringConstraints

from app.authorization_models import AuthorizationResponse


Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]

IntegrityAlgorithm = Literal["SHA-256"]
IntegritySchemaVersion = Literal[1]

IntegrityFailureCode = Literal[
    "record_count_mismatch",
    "sequence_mismatch",
    "previous_hash_mismatch",
    "payload_hash_mismatch",
    "record_hash_mismatch",
    "algorithm_mismatch",
    "schema_version_mismatch",
    "created_at_mismatch",
    "payload_unreadable",
    "head_hash_mismatch",
]


class DecisionIntegrityProof(BaseModel):
    decision_id: UUID
    project_id: UUID
    sequence_number: int = Field(ge=1)
    previous_hash: Sha256Digest | None = None
    payload_hash: Sha256Digest
    record_hash: Sha256Digest
    algorithm: IntegrityAlgorithm = "SHA-256"
    schema_version: IntegritySchemaVersion = 1
    created_at: datetime


class DecisionIntegrityProofPage(BaseModel):
    items: list[DecisionIntegrityProof]
    total: int
    limit: int
    offset: int


class IntegrityVerificationFailure(BaseModel):
    code: IntegrityFailureCode
    message: str
    decision_id: UUID | None = None
    sequence_number: int | None = Field(default=None, ge=1)
    expected: str | None = None
    actual: str | None = None


class DecisionIntegrityVerification(BaseModel):
    project_id: UUID
    algorithm: IntegrityAlgorithm = "SHA-256"
    verified: bool
    total_decisions: int = Field(ge=0)
    checked_records: int = Field(ge=0)
    head_hash: Sha256Digest | None = None
    verified_at: datetime
    failure: IntegrityVerificationFailure | None = None


class VerifiableDecisionRecord(BaseModel):
    decision: AuthorizationResponse
    integrity: DecisionIntegrityProof

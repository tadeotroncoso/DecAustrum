import hashlib
import json
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel

from app.authorization_models import AuthorizationRequest


def build_request_fingerprint(
    request: AuthorizationRequest,
) -> str:
    canonical_request = json.dumps(
        request.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    return hashlib.sha256(
        canonical_request.encode("utf-8")
    ).hexdigest()

class IdempotencyRecord(BaseModel):
    project_id: UUID
    idempotency_key: str
    request_fingerprint: str
    decision_id: UUID
    created_at: datetime
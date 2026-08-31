"""Typed response models for the DecAustrum runtime API."""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping, Sequence, cast
from uuid import UUID

Decision = Literal["ALLOW", "REQUIRE_APPROVAL", "DENY"]
ApprovalStatus = Literal[
    "PENDING",
    "APPROVED",
    "REJECTED",
    "EXPIRED",
]
Operator = Literal[
    "greater_than",
    "less_than",
    "equals",
    "not_equals",
]
ConditionMatch = Literal["all", "any"]
JsonObject = dict[str, Any]


def _mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a JSON object")
    return value


def _sequence(value: Any, field_name: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(
        value,
        (str, bytes, bytearray),
    ):
        raise ValueError(f"{field_name} must be a JSON array")
    return value


def _required(data: Mapping[str, Any], field_name: str) -> Any:
    if field_name not in data:
        raise ValueError(f"response is missing {field_name}")
    return data[field_name]


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _optional_text(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _text(value, field_name)


def _integer(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer")
    return value


def _optional_integer(value: Any, field_name: str) -> int | None:
    if value is None:
        return None
    return _integer(value, field_name)


def _boolean(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field_name} must be a boolean")
    return value


def _uuid(value: Any, field_name: str) -> UUID:
    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError(f"{field_name} must be a UUID") from exc


def _timestamp(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp")

    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be an ISO-8601 timestamp"
        ) from exc

    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed


def _optional_timestamp(
    value: Any,
    field_name: str,
) -> datetime | None:
    if value is None:
        return None
    return _timestamp(value, field_name)


def _choice(
    value: Any,
    field_name: str,
    choices: set[str],
) -> str:
    parsed = _text(value, field_name)
    if parsed not in choices:
        raise ValueError(f"{field_name} has an unsupported value")
    return parsed


def _json_object(value: Any, field_name: str) -> JsonObject:
    return deepcopy(dict(_mapping(value, field_name)))


@dataclass(frozen=True, slots=True)
class ConditionEvidence:
    field: str
    operator: Operator
    actual_value: Any
    expected_value: Any
    matched: bool

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ConditionEvidence":
        data = _mapping(value, "condition evidence")
        return cls(
            field=_text(_required(data, "field"), "field"),
            operator=cast(
                Operator,
                _choice(
                    _required(data, "operator"),
                    "operator",
                    {
                        "greater_than",
                        "less_than",
                        "equals",
                        "not_equals",
                    },
                ),
            ),
            actual_value=deepcopy(_required(data, "actual_value")),
            expected_value=deepcopy(
                _required(data, "expected_value")
            ),
            matched=_boolean(
                _required(data, "matched"),
                "matched",
            ),
        )


@dataclass(frozen=True, slots=True)
class PolicyEvidence:
    match: ConditionMatch
    conditions: tuple[ConditionEvidence, ...]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicyEvidence":
        data = _mapping(value, "policy evidence")
        conditions = _sequence(
            _required(data, "conditions"),
            "conditions",
        )
        return cls(
            match=cast(
                ConditionMatch,
                _choice(
                    _required(data, "match"),
                    "match",
                    {"all", "any"},
                ),
            ),
            conditions=tuple(
                ConditionEvidence.from_dict(
                    _mapping(item, "condition evidence")
                )
                for item in conditions
            ),
        )


@dataclass(frozen=True, slots=True)
class PolicyTraceEntry:
    policy_id: str
    policy_version: int
    decision: Decision
    reason: str
    matched: bool
    evidence: PolicyEvidence

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicyTraceEntry":
        data = _mapping(value, "policy trace entry")
        return cls(
            policy_id=_text(
                _required(data, "policy_id"),
                "policy_id",
            ),
            policy_version=_integer(
                _required(data, "policy_version"),
                "policy_version",
            ),
            decision=cast(
                Decision,
                _choice(
                    _required(data, "decision"),
                    "decision",
                    {"ALLOW", "REQUIRE_APPROVAL", "DENY"},
                ),
            ),
            reason=_text(_required(data, "reason"), "reason"),
            matched=_boolean(
                _required(data, "matched"),
                "matched",
            ),
            evidence=PolicyEvidence.from_dict(
                _mapping(
                    _required(data, "evidence"),
                    "evidence",
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    decision_id: UUID
    project_id: UUID
    evaluated_at: datetime
    decision: Decision
    policy: str | None
    policy_version: int | None
    reason: str
    evidence: PolicyEvidence | None
    agent: str
    action: str
    context: JsonObject = field(repr=False)
    trace: tuple[PolicyTraceEntry, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def denied(self) -> bool:
        return self.decision == "DENY"

    @property
    def requires_approval(self) -> bool:
        return self.decision == "REQUIRE_APPROVAL"

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
    ) -> "AuthorizationDecision":
        data = _mapping(value, "authorization decision")
        raw_evidence = data.get("evidence")
        raw_trace = _sequence(
            _required(data, "trace"),
            "trace",
        )
        return cls(
            decision_id=_uuid(
                _required(data, "decision_id"),
                "decision_id",
            ),
            project_id=_uuid(
                _required(data, "project_id"),
                "project_id",
            ),
            evaluated_at=_timestamp(
                _required(data, "evaluated_at"),
                "evaluated_at",
            ),
            decision=cast(
                Decision,
                _choice(
                    _required(data, "decision"),
                    "decision",
                    {"ALLOW", "REQUIRE_APPROVAL", "DENY"},
                ),
            ),
            policy=_optional_text(data.get("policy"), "policy"),
            policy_version=_optional_integer(
                data.get("policy_version"),
                "policy_version",
            ),
            reason=_text(_required(data, "reason"), "reason"),
            evidence=(
                None
                if raw_evidence is None
                else PolicyEvidence.from_dict(
                    _mapping(raw_evidence, "evidence")
                )
            ),
            agent=_text(_required(data, "agent"), "agent"),
            action=_text(_required(data, "action"), "action"),
            context=_json_object(
                _required(data, "context"),
                "context",
            ),
            trace=tuple(
                PolicyTraceEntry.from_dict(
                    _mapping(item, "policy trace entry")
                )
                for item in raw_trace
            ),
        )


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    decision_id: UUID
    status: ApprovalStatus
    requested_at: datetime
    expires_at: datetime | None
    resolved_at: datetime | None
    resolved_by: str | None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ApprovalRecord":
        data = _mapping(value, "approval")
        return cls(
            decision_id=_uuid(
                _required(data, "decision_id"),
                "decision_id",
            ),
            status=cast(
                ApprovalStatus,
                _choice(
                    _required(data, "status"),
                    "status",
                    {"PENDING", "APPROVED", "REJECTED", "EXPIRED"},
                ),
            ),
            requested_at=_timestamp(
                _required(data, "requested_at"),
                "requested_at",
            ),
            expires_at=_optional_timestamp(
                data.get("expires_at"),
                "expires_at",
            ),
            resolved_at=_optional_timestamp(
                data.get("resolved_at"),
                "resolved_at",
            ),
            resolved_by=_optional_text(
                data.get("resolved_by"),
                "resolved_by",
            ),
        )


@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    decision_id: UUID
    status: ApprovalStatus
    requested_at: datetime
    expires_at: datetime | None
    resolved_at: datetime | None
    resolved_by: str | None
    execution_grant: str = field(repr=False)
    grant_id: UUID
    grant_expires_at: datetime

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ApprovalGrant":
        data = _mapping(value, "approval grant")
        approval = ApprovalRecord.from_dict(data)
        return cls(
            decision_id=approval.decision_id,
            status=approval.status,
            requested_at=approval.requested_at,
            expires_at=approval.expires_at,
            resolved_at=approval.resolved_at,
            resolved_by=approval.resolved_by,
            execution_grant=_text(
                _required(data, "execution_grant"),
                "execution_grant",
            ),
            grant_id=_uuid(
                _required(data, "grant_id"),
                "grant_id",
            ),
            grant_expires_at=_timestamp(
                _required(data, "grant_expires_at"),
                "grant_expires_at",
            ),
        )


@dataclass(frozen=True, slots=True)
class ApprovalPage:
    items: tuple[ApprovalRecord, ...]
    total: int
    limit: int
    offset: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ApprovalPage":
        data = _mapping(value, "approval page")
        items = _sequence(_required(data, "items"), "items")
        return cls(
            items=tuple(
                ApprovalRecord.from_dict(_mapping(item, "approval"))
                for item in items
            ),
            total=_integer(_required(data, "total"), "total"),
            limit=_integer(_required(data, "limit"), "limit"),
            offset=_integer(_required(data, "offset"), "offset"),
        )


@dataclass(frozen=True, slots=True)
class ExecutionGrantConsumption:
    authorized: Literal[True]
    grant_id: UUID
    decision_id: UUID
    consumed_at: datetime
    consumed_by: str
    agent: str
    action: str

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
    ) -> "ExecutionGrantConsumption":
        data = _mapping(value, "execution grant consumption")
        authorized = _boolean(
            _required(data, "authorized"),
            "authorized",
        )
        if not authorized:
            raise ValueError("authorized must be true")
        return cls(
            authorized=True,
            grant_id=_uuid(
                _required(data, "grant_id"),
                "grant_id",
            ),
            decision_id=_uuid(
                _required(data, "decision_id"),
                "decision_id",
            ),
            consumed_at=_timestamp(
                _required(data, "consumed_at"),
                "consumed_at",
            ),
            consumed_by=_text(
                _required(data, "consumed_by"),
                "consumed_by",
            ),
            agent=_text(_required(data, "agent"), "agent"),
            action=_text(_required(data, "action"), "action"),
        )


@dataclass(frozen=True, slots=True)
class HealthStatus:
    status: Literal["ok", "unavailable"]

    @property
    def ready(self) -> bool:
        return self.status == "ok"

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "HealthStatus":
        data = _mapping(value, "health response")
        return cls(
            status=cast(
                Literal["ok", "unavailable"],
                _choice(
                    _required(data, "status"),
                    "status",
                    {"ok", "unavailable"},
                ),
            )
        )


__all__ = [
    "ApprovalGrant",
    "ApprovalPage",
    "ApprovalRecord",
    "ApprovalStatus",
    "AuthorizationDecision",
    "ConditionEvidence",
    "Decision",
    "ExecutionGrantConsumption",
    "HealthStatus",
    "JsonObject",
    "PolicyEvidence",
    "PolicyTraceEntry",
]

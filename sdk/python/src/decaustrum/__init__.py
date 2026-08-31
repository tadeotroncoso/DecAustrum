"""Public API for the DecAustrum Python SDK."""

from decaustrum._version import __version__
from decaustrum.async_client import AsyncDecAustrumClient
from decaustrum.client import DecAustrumClient
from decaustrum.errors import (
    ActionDeniedError,
    ApprovalRequiredError,
    ApprovalWaitTimeoutError,
    AuthenticationError,
    ConflictError,
    DecAustrumAPIError,
    DecAustrumError,
    DecAustrumProtocolError,
    DecAustrumTransportError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from decaustrum.guard import (
    AsyncDecAustrumGuard,
    DecAustrumGuard,
    GuardedExecution,
)
from decaustrum.models import (
    ApprovalGrant,
    ApprovalPage,
    ApprovalRecord,
    AuthorizationDecision,
    ConditionEvidence,
    ExecutionGrantConsumption,
    HealthStatus,
    PolicyEvidence,
    PolicyTraceEntry,
)

__all__ = [
    "ActionDeniedError",
    "ApprovalGrant",
    "ApprovalPage",
    "ApprovalRecord",
    "ApprovalRequiredError",
    "ApprovalWaitTimeoutError",
    "AsyncDecAustrumClient",
    "AsyncDecAustrumGuard",
    "AuthenticationError",
    "AuthorizationDecision",
    "ConditionEvidence",
    "ConflictError",
    "ExecutionGrantConsumption",
    "GuardedExecution",
    "HealthStatus",
    "NotFoundError",
    "PolicyEvidence",
    "PolicyTraceEntry",
    "RateLimitError",
    "DecAustrumAPIError",
    "DecAustrumClient",
    "DecAustrumError",
    "DecAustrumGuard",
    "DecAustrumProtocolError",
    "DecAustrumTransportError",
    "ServerError",
    "ValidationError",
    "__version__",
]

"""Public API for the RegTrace Python SDK."""

from regtrace.async_client import AsyncRegTraceClient
from regtrace.client import RegTraceClient
from regtrace._version import __version__
from regtrace.errors import (
    ActionDeniedError,
    ApprovalRequiredError,
    ApprovalWaitTimeoutError,
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    RegTraceAPIError,
    RegTraceError,
    RegTraceProtocolError,
    RegTraceTransportError,
    ServerError,
    ValidationError,
)
from regtrace.guard import (
    AsyncRegTraceGuard,
    GuardedExecution,
    RegTraceGuard,
)
from regtrace.models import (
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
    "AsyncRegTraceClient",
    "AsyncRegTraceGuard",
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
    "RegTraceAPIError",
    "RegTraceClient",
    "RegTraceError",
    "RegTraceGuard",
    "RegTraceProtocolError",
    "RegTraceTransportError",
    "ServerError",
    "ValidationError",
    "__version__",
]

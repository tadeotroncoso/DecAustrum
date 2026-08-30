"""Exceptions raised by the RegTrace Python SDK."""

from typing import Any
from uuid import UUID

from regtrace.models import AuthorizationDecision


class RegTraceError(Exception):
    """Base class for all SDK errors."""


class RegTraceTransportError(RegTraceError):
    """The API could not be reached or timed out."""


class RegTraceProtocolError(RegTraceError):
    """The server returned a response that violates the API contract."""


class RegTraceAPIError(RegTraceError):
    """A structured non-success response returned by RegTrace."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        request_id: str | None = None,
        details: Any = None,
        retry_after: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.request_id = request_id
        self.details = details
        self.retry_after = retry_after

        request_suffix = (
            f" [request_id={request_id}]" if request_id else ""
        )
        super().__init__(
            f"RegTrace API error {status_code} ({code}): "
            f"{message}{request_suffix}"
        )


class AuthenticationError(RegTraceAPIError):
    """The project API key is missing, invalid, or not authorized."""


class NotFoundError(RegTraceAPIError):
    """The requested RegTrace resource does not exist."""


class ConflictError(RegTraceAPIError):
    """The request conflicts with persisted lifecycle state."""


class ValidationError(RegTraceAPIError):
    """The request is not valid for the API contract or policy context."""


class RateLimitError(RegTraceAPIError):
    """The project or client exceeded its configured request rate."""


class ServerError(RegTraceAPIError):
    """RegTrace failed while processing the request."""


class ActionDeniedError(RegTraceError):
    """A guarded business operation was denied by policy."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Action '{decision.action}' was denied by RegTrace: "
            f"{decision.reason}"
        )


class ApprovalRequiredError(RegTraceError):
    """A guarded operation needs human approval before execution."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Action '{decision.action}' requires approval for "
            f"decision '{decision.decision_id}'."
        )


class ApprovalWaitTimeoutError(RegTraceError):
    """Polling did not reach a terminal approval state in time."""

    def __init__(self, decision_id: UUID, timeout: float) -> None:
        self.decision_id = decision_id
        self.timeout = timeout
        super().__init__(
            f"Approval for decision '{decision_id}' did not resolve "
            f"within {timeout:g} seconds."
        )

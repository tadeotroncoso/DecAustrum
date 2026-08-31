"""Exceptions raised by the DecAustrum Python SDK."""

from typing import Any
from uuid import UUID

from decaustrum.models import AuthorizationDecision


class DecAustrumError(Exception):
    """Base class for all SDK errors."""


class DecAustrumTransportError(DecAustrumError):
    """The API could not be reached or timed out."""


class DecAustrumProtocolError(DecAustrumError):
    """The server returned a response that violates the API contract."""


class DecAustrumAPIError(DecAustrumError):
    """A structured non-success response returned by DecAustrum."""

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
            f"DecAustrum API error {status_code} ({code}): "
            f"{message}{request_suffix}"
        )


class AuthenticationError(DecAustrumAPIError):
    """The project API key is missing, invalid, or not authorized."""


class NotFoundError(DecAustrumAPIError):
    """The requested DecAustrum resource does not exist."""


class ConflictError(DecAustrumAPIError):
    """The request conflicts with persisted lifecycle state."""


class ValidationError(DecAustrumAPIError):
    """The request is not valid for the API contract or policy context."""


class RateLimitError(DecAustrumAPIError):
    """The project or client exceeded its configured request rate."""


class ServerError(DecAustrumAPIError):
    """DecAustrum failed while processing the request."""


class ActionDeniedError(DecAustrumError):
    """A guarded business operation was denied by policy."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Action '{decision.action}' was denied by DecAustrum: "
            f"{decision.reason}"
        )


class ApprovalRequiredError(DecAustrumError):
    """A guarded operation needs human approval before execution."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        self.decision = decision
        super().__init__(
            f"Action '{decision.action}' requires approval for "
            f"decision '{decision.decision_id}'."
        )


class ApprovalWaitTimeoutError(DecAustrumError):
    """Polling did not reach a terminal approval state in time."""

    def __init__(self, decision_id: UUID, timeout: float) -> None:
        self.decision_id = decision_id
        self.timeout = timeout
        super().__init__(
            f"Approval for decision '{decision_id}' did not resolve "
            f"within {timeout:g} seconds."
        )

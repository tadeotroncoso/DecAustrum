"""Framework-independent enforcement helpers for business operations."""

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from decaustrum.async_client import AsyncDecAustrumClient
from decaustrum.client import DecAustrumClient
from decaustrum.errors import (
    ActionDeniedError,
    ApprovalRequiredError,
)
from decaustrum.models import (
    AuthorizationDecision,
    ExecutionGrantConsumption,
)


ResultT = TypeVar("ResultT")


@dataclass(frozen=True, slots=True)
class GuardedExecution(Generic[ResultT]):
    """Result of a business operation executed behind DecAustrum."""

    value: ResultT
    authorization: AuthorizationDecision | None = None
    consumption: ExecutionGrantConsumption | None = None

    def __post_init__(self) -> None:
        if (self.authorization is None) == (self.consumption is None):
            raise ValueError(
                "Guarded execution requires exactly one authorization "
                "or grant consumption record."
            )


class DecAustrumGuard:
    """Runs synchronous operations only after successful authorization."""

    def __init__(self, client: DecAustrumClient) -> None:
        self.client = client

    def execute(
        self,
        *,
        agent: str,
        action: str,
        context: Mapping[str, Any],
        operation: Callable[[], ResultT],
        idempotency_key: str | None = None,
    ) -> GuardedExecution[ResultT]:
        """Authorize and run an operation when the decision is ALLOW.

        DENY raises ``ActionDeniedError``. REQUIRE_APPROVAL raises
        ``ApprovalRequiredError`` and leaves the operation untouched.
        """

        decision = self.client.authorize(
            agent=agent,
            action=action,
            context=context,
            idempotency_key=idempotency_key,
        )

        if decision.denied:
            raise ActionDeniedError(decision)
        if decision.requires_approval:
            raise ApprovalRequiredError(decision)

        return GuardedExecution(
            value=operation(),
            authorization=decision,
        )

    def execute_approved(
        self,
        *,
        execution_grant: str,
        agent: str,
        action: str,
        context: Mapping[str, Any],
        consumed_by: str,
        operation: Callable[[], ResultT],
    ) -> GuardedExecution[ResultT]:
        """Consume a one-time grant, then run the bound operation.

        The grant is deliberately consumed before the callback. If the
        callback fails, callers must re-authorize rather than replaying it.
        """

        consumption = self.client.consume_execution_grant(
            execution_grant=execution_grant,
            agent=agent,
            action=action,
            context=context,
            consumed_by=consumed_by,
        )
        return GuardedExecution(
            value=operation(),
            consumption=consumption,
        )


class AsyncDecAustrumGuard:
    """Runs async operations only after successful authorization."""

    def __init__(self, client: AsyncDecAustrumClient) -> None:
        self.client = client

    async def execute(
        self,
        *,
        agent: str,
        action: str,
        context: Mapping[str, Any],
        operation: Callable[[], Awaitable[ResultT]],
        idempotency_key: str | None = None,
    ) -> GuardedExecution[ResultT]:
        decision = await self.client.authorize(
            agent=agent,
            action=action,
            context=context,
            idempotency_key=idempotency_key,
        )

        if decision.denied:
            raise ActionDeniedError(decision)
        if decision.requires_approval:
            raise ApprovalRequiredError(decision)

        return GuardedExecution(
            value=await operation(),
            authorization=decision,
        )

    async def execute_approved(
        self,
        *,
        execution_grant: str,
        agent: str,
        action: str,
        context: Mapping[str, Any],
        consumed_by: str,
        operation: Callable[[], Awaitable[ResultT]],
    ) -> GuardedExecution[ResultT]:
        consumption = await self.client.consume_execution_grant(
            execution_grant=execution_grant,
            agent=agent,
            action=action,
            context=context,
            consumed_by=consumed_by,
        )
        return GuardedExecution(
            value=await operation(),
            consumption=consumption,
        )


__all__ = [
    "AsyncDecAustrumGuard",
    "GuardedExecution",
    "DecAustrumGuard",
]

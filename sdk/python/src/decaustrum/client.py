"""Synchronous client for the DecAustrum runtime API."""

import os
import time
from typing import Any, Mapping
from uuid import UUID

import httpx

from decaustrum._http import (
    DEFAULT_BASE_URL,
    DEFAULT_TIMEOUT,
    build_headers,
    build_url,
    normalize_api_key,
    normalize_base_url,
    normalize_context,
    normalize_idempotency_key,
    normalize_identifier,
    normalize_optional_reason,
    normalize_page,
    normalize_timeout,
    normalize_uuid,
    parse_response,
)
from decaustrum.errors import (
    ApprovalWaitTimeoutError,
    DecAustrumTransportError,
)
from decaustrum.models import (
    ApprovalGrant,
    ApprovalPage,
    ApprovalRecord,
    ApprovalStatus,
    AuthorizationDecision,
    ExecutionGrantConsumption,
    HealthStatus,
)


class DecAustrumClient:
    """Typed synchronous client scoped to one DecAustrum project key."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._api_key = normalize_api_key(api_key)
        self._base_url = normalize_base_url(base_url)
        self._timeout = normalize_timeout(timeout)
        self._owns_http_client = http_client is None
        self._http_client = http_client or httpx.Client(
            timeout=self._timeout
        )
        self._closed = False

    @classmethod
    def from_environment(
        cls,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        http_client: httpx.Client | None = None,
    ) -> "DecAustrumClient":
        api_key = os.getenv("DECAUSTRUM_API_KEY")
        if not api_key:
            raise ValueError("DECAUSTRUM_API_KEY must be configured")
        return cls(
            api_key=api_key,
            base_url=os.getenv(
                "DECAUSTRUM_BASE_URL",
                DEFAULT_BASE_URL,
            ),
            timeout=timeout,
            http_client=http_client,
        )

    def __enter__(self) -> "DecAustrumClient":
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        if self._owns_http_client:
            self._http_client.close()
        self._closed = True

    def health(self) -> HealthStatus:
        response = self._request("GET", "/health")
        return parse_response(response, HealthStatus.from_dict)

    def authorize(
        self,
        *,
        agent: str,
        action: str,
        context: Mapping[str, Any],
        idempotency_key: str | None = None,
    ) -> AuthorizationDecision:
        normalized_key = normalize_idempotency_key(idempotency_key)
        extra_headers = (
            {"Idempotency-Key": normalized_key}
            if normalized_key is not None
            else None
        )
        response = self._request(
            "POST",
            "/v1/authorize",
            json_body={
                "agent": normalize_identifier(agent, "agent"),
                "action": normalize_identifier(action, "action"),
                "context": normalize_context(context),
            },
            extra_headers=extra_headers,
        )
        return parse_response(
            response,
            AuthorizationDecision.from_dict,
        )

    def get_decision(
        self,
        decision_id: UUID | str,
    ) -> AuthorizationDecision:
        normalized_id = normalize_uuid(decision_id, "decision_id")
        response = self._request(
            "GET",
            f"/v1/decisions/{normalized_id}",
        )
        return parse_response(
            response,
            AuthorizationDecision.from_dict,
        )

    def list_approvals(
        self,
        *,
        status: ApprovalStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> ApprovalPage:
        normalized_limit, normalized_offset = normalize_page(
            limit,
            offset,
        )
        if status is not None and status not in {
            "PENDING",
            "APPROVED",
            "REJECTED",
            "EXPIRED",
        }:
            raise ValueError("status is not a valid approval status")
        params: dict[str, Any] = {
            "limit": normalized_limit,
            "offset": normalized_offset,
        }
        if status is not None:
            params["status"] = status
        response = self._request(
            "GET",
            "/v1/approvals",
            params=params,
        )
        return parse_response(response, ApprovalPage.from_dict)

    def get_approval(
        self,
        decision_id: UUID | str,
    ) -> ApprovalRecord:
        normalized_id = normalize_uuid(decision_id, "decision_id")
        response = self._request(
            "GET",
            f"/v1/approvals/{normalized_id}",
        )
        return parse_response(response, ApprovalRecord.from_dict)

    def wait_for_approval(
        self,
        decision_id: UUID | str,
        *,
        timeout: float = 300.0,
        poll_interval: float = 1.0,
    ) -> ApprovalRecord:
        normalized_id = normalize_uuid(decision_id, "decision_id")
        normalized_timeout = normalize_timeout(timeout)
        normalized_interval = normalize_timeout(poll_interval)
        deadline = time.monotonic() + normalized_timeout

        while True:
            approval = self.get_approval(normalized_id)
            if approval.status != "PENDING":
                return approval

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ApprovalWaitTimeoutError(
                    normalized_id,
                    normalized_timeout,
                )
            time.sleep(min(normalized_interval, remaining))

    def approve(
        self,
        decision_id: UUID | str,
        *,
        resolved_by: str,
        reason: str | None = None,
    ) -> ApprovalGrant:
        normalized_id = normalize_uuid(decision_id, "decision_id")
        response = self._request(
            "POST",
            f"/v1/approvals/{normalized_id}/approve",
            json_body={
                "resolved_by": normalize_identifier(
                    resolved_by,
                    "resolved_by",
                ),
                "reason": normalize_optional_reason(reason),
            },
        )
        return parse_response(response, ApprovalGrant.from_dict)

    def reject(
        self,
        decision_id: UUID | str,
        *,
        resolved_by: str,
        reason: str | None = None,
    ) -> ApprovalRecord:
        normalized_id = normalize_uuid(decision_id, "decision_id")
        response = self._request(
            "POST",
            f"/v1/approvals/{normalized_id}/reject",
            json_body={
                "resolved_by": normalize_identifier(
                    resolved_by,
                    "resolved_by",
                ),
                "reason": normalize_optional_reason(reason),
            },
        )
        return parse_response(response, ApprovalRecord.from_dict)

    def consume_execution_grant(
        self,
        *,
        execution_grant: str,
        agent: str,
        action: str,
        context: Mapping[str, Any],
        consumed_by: str,
    ) -> ExecutionGrantConsumption:
        response = self._request(
            "POST",
            "/v1/execution-grants/consume",
            json_body={
                "execution_grant": normalize_identifier(
                    execution_grant,
                    "execution_grant",
                ),
                "agent": normalize_identifier(agent, "agent"),
                "action": normalize_identifier(action, "action"),
                "context": normalize_context(context),
                "consumed_by": normalize_identifier(
                    consumed_by,
                    "consumed_by",
                ),
            },
        )
        return parse_response(
            response,
            ExecutionGrantConsumption.from_dict,
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: Mapping[str, Any] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        self._ensure_open()

        try:
            return self._http_client.request(
                method,
                build_url(self._base_url, path),
                headers=build_headers(
                    self._api_key,
                    extra_headers,
                ),
                json=json_body,
                params=params,
            )
        except httpx.TimeoutException as exc:
            raise DecAustrumTransportError(
                f"DecAustrum request timed out after "
                f"{self._timeout:g} seconds."
            ) from exc
        except httpx.RequestError as exc:
            raise DecAustrumTransportError(
                "DecAustrum could not be reached."
            ) from exc

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("DecAustrumClient is closed")


__all__ = ["DecAustrumClient"]

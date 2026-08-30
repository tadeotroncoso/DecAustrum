import asyncio
from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest

from regtrace import (
    ActionDeniedError,
    ApprovalGrant,
    ApprovalRequiredError,
    AsyncRegTraceClient,
    AuthenticationError,
    ConflictError,
    NotFoundError,
    RateLimitError,
    RegTraceClient,
    RegTraceGuard,
    RegTraceProtocolError,
    RegTraceTransportError,
    ServerError,
    ValidationError as RegTraceValidationError,
)


DECISION_ID = uuid4()
PROJECT_ID = uuid4()
GRANT_ID = uuid4()
EVALUATED_AT = "2026-08-30T10:00:00+00:00"


def decision_payload(decision: str = "ALLOW") -> dict:
    policy = None if decision == "ALLOW" else "test-policy"
    policy_version = None if policy is None else 1
    return {
        "decision_id": str(DECISION_ID),
        "project_id": str(PROJECT_ID),
        "evaluated_at": EVALUATED_AT,
        "decision": decision,
        "policy": policy,
        "policy_version": policy_version,
        "reason": "Test decision.",
        "evidence": None,
        "agent": "test-agent",
        "action": "test-action",
        "context": {"resource_id": "resource-1"},
        "trace": [],
    }


def approval_payload(status: str = "PENDING") -> dict:
    terminal = status != "PENDING"
    return {
        "decision_id": str(DECISION_ID),
        "status": status,
        "requested_at": EVALUATED_AT,
        "expires_at": "2026-08-30T11:00:00+00:00",
        "resolved_at": EVALUATED_AT if terminal else None,
        "resolved_by": "reviewer" if terminal else None,
    }


def sdk_client(handler) -> tuple[RegTraceClient, httpx.Client]:
    http_client = httpx.Client(transport=httpx.MockTransport(handler))
    return (
        RegTraceClient(
            api_key="project-key",
            base_url="https://regtrace.example",
            http_client=http_client,
        ),
        http_client,
    )


def test_sync_client_sends_auth_idempotency_and_parses_decision():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == (
            "https://regtrace.example/v1/authorize"
        )
        assert request.headers["X-API-Key"] == "project-key"
        assert request.headers["Idempotency-Key"] == "request-42"
        assert request.headers["User-Agent"] == (
            "regtrace-python/0.1.0"
        )
        assert request.headers["X-Request-ID"]
        return httpx.Response(200, json=decision_payload())

    client, http_client = sdk_client(handler)
    try:
        decision = client.authorize(
            agent=" test-agent ",
            action=" test-action ",
            context={"resource_id": "resource-1"},
            idempotency_key="request-42",
        )
    finally:
        http_client.close()

    assert decision.decision_id == DECISION_ID
    assert decision.project_id == PROJECT_ID
    assert decision.allowed is True
    assert decision.denied is False
    assert decision.requires_approval is False
    assert decision.evaluated_at.tzinfo is not None


@pytest.mark.parametrize(
    ("status_code", "error_type"),
    [
        (401, AuthenticationError),
        (403, AuthenticationError),
        (404, NotFoundError),
        (409, ConflictError),
        (422, RegTraceValidationError),
        (429, RateLimitError),
        (503, ServerError),
    ],
)
def test_sdk_maps_structured_api_errors(status_code, error_type):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={
                "X-Request-ID": "request-123",
                "Retry-After": "9",
            },
            json={
                "detail": {
                    "code": "test_error",
                    "message": "Test error message.",
                }
            },
        )

    client, http_client = sdk_client(handler)
    try:
        with pytest.raises(error_type) as captured:
            client.get_decision(DECISION_ID)
    finally:
        http_client.close()

    assert captured.value.status_code == status_code
    assert captured.value.code == "test_error"
    assert captured.value.request_id == "request-123"
    assert captured.value.retry_after == "9"


def test_sdk_maps_fastapi_validation_list_without_losing_details():
    details = [
        {
            "type": "missing",
            "loc": ["body", "agent"],
            "msg": "Field required",
        }
    ]

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"detail": details})

    client, http_client = sdk_client(handler)
    try:
        with pytest.raises(RegTraceValidationError) as captured:
            client.get_decision(DECISION_ID)
    finally:
        http_client.close()

    assert captured.value.code == "validation_error"
    assert captured.value.details == details


def test_sdk_rejects_success_response_outside_contract():
    def handler(_: httpx.Request) -> httpx.Response:
        payload = decision_payload()
        payload.pop("decision_id")
        return httpx.Response(200, json=payload)

    client, http_client = sdk_client(handler)
    try:
        with pytest.raises(RegTraceProtocolError):
            client.get_decision(DECISION_ID)
    finally:
        http_client.close()


def test_sdk_wraps_network_failures():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client, http_client = sdk_client(handler)
    try:
        with pytest.raises(RegTraceTransportError):
            client.health()
    finally:
        http_client.close()


def test_sdk_validates_context_before_sending_request():
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=decision_payload())

    client, http_client = sdk_client(handler)
    try:
        with pytest.raises(ValueError, match="valid JSON"):
            client.authorize(
                agent="agent",
                action="action",
                context={"invalid": {1, 2, 3}},
            )
    finally:
        http_client.close()

    assert calls == 0


def test_approval_grant_repr_never_contains_bearer_token():
    payload = {
        **approval_payload("APPROVED"),
        "execution_grant": "rgt_exec_v1.super-secret-token",
        "grant_id": str(GRANT_ID),
        "grant_expires_at": "2026-08-30T10:05:00+00:00",
    }

    grant = ApprovalGrant.from_dict(payload)

    assert grant.execution_grant == "rgt_exec_v1.super-secret-token"
    assert "super-secret-token" not in repr(grant)


@pytest.mark.parametrize(
    ("decision", "error_type"),
    [
        ("DENY", ActionDeniedError),
        ("REQUIRE_APPROVAL", ApprovalRequiredError),
    ],
)
def test_guard_never_calls_operation_without_allow(decision, error_type):
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=decision_payload(decision))

    client, http_client = sdk_client(handler)
    guard = RegTraceGuard(client)
    operation_calls = 0

    def operation():
        nonlocal operation_calls
        operation_calls += 1

    try:
        with pytest.raises(error_type):
            guard.execute(
                agent="test-agent",
                action="test-action",
                context={"resource_id": "resource-1"},
                operation=operation,
            )
    finally:
        http_client.close()

    assert operation_calls == 0


def test_guard_calls_operation_once_after_allow():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=decision_payload())

    client, http_client = sdk_client(handler)
    guard = RegTraceGuard(client)
    operation_calls = 0

    def operation() -> str:
        nonlocal operation_calls
        operation_calls += 1
        return "completed"

    try:
        result = guard.execute(
            agent="test-agent",
            action="test-action",
            context={"resource_id": "resource-1"},
            operation=operation,
        )
    finally:
        http_client.close()

    assert result.value == "completed"
    assert result.authorization is not None
    assert result.consumption is None
    assert operation_calls == 1


def test_guard_consumes_grant_before_calling_approved_operation():
    consumed = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal consumed
        assert request.url.path == "/v1/execution-grants/consume"
        consumed = True
        return httpx.Response(
            200,
            json={
                "authorized": True,
                "grant_id": str(GRANT_ID),
                "decision_id": str(DECISION_ID),
                "consumed_at": EVALUATED_AT,
                "consumed_by": "runtime",
                "agent": "test-agent",
                "action": "test-action",
            },
        )

    client, http_client = sdk_client(handler)
    guard = RegTraceGuard(client)

    def operation() -> str:
        assert consumed is True
        return "completed"

    try:
        result = guard.execute_approved(
            execution_grant="rgt_exec_v1.token",
            agent="test-agent",
            action="test-action",
            context={"resource_id": "resource-1"},
            consumed_by="runtime",
            operation=operation,
        )
    finally:
        http_client.close()

    assert result.value == "completed"
    assert result.authorization is None
    assert result.consumption is not None


def test_async_client_uses_same_typed_contract():
    async def run_test():
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers["X-API-Key"] == "async-key"
            return httpx.Response(200, json=decision_payload())

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        ) as http_client:
            client = AsyncRegTraceClient(
                api_key="async-key",
                base_url="https://regtrace.example",
                http_client=http_client,
            )
            return await client.authorize(
                agent="test-agent",
                action="test-action",
                context={"resource_id": "resource-1"},
            )

    decision = asyncio.run(run_test())

    assert decision.decision_id == DECISION_ID
    assert decision.allowed is True


def test_sdk_environment_constructor(monkeypatch):
    monkeypatch.setenv("REGTRACE_API_KEY", "environment-key")
    monkeypatch.setenv(
        "REGTRACE_BASE_URL",
        "https://regtrace.internal/prefix/",
    )
    http_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={"status": "ok"},
            )
        )
    )
    try:
        client = RegTraceClient.from_environment(
            http_client=http_client
        )
        assert client.health().ready is True
    finally:
        http_client.close()


def test_sdk_timestamp_models_keep_timezone():
    decision = decision_payload()
    decision["evaluated_at"] = datetime.now(timezone.utc).isoformat()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=decision)

    client, http_client = sdk_client(handler)
    try:
        parsed = client.get_decision(DECISION_ID)
    finally:
        http_client.close()

    assert parsed.evaluated_at.utcoffset() is not None

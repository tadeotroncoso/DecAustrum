import asyncio
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from app.bootstrap import bootstrap_default_project
from app.evidence_store import EvidenceStore
from app.main import app, get_evidence_store
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID
from decaustrum import (
    ActionDeniedError,
    ApprovalRequiredError,
    AsyncDecAustrumClient,
    AsyncDecAustrumGuard,
    AuthenticationError,
    ConflictError,
    DecAustrumClient,
    DecAustrumGuard,
)


TEST_API_KEY = "python-sdk-project-key"
TEST_ADMIN_API_KEY = "python-sdk-admin-key"
TEST_EXECUTION_SECRET = (
    "python-sdk-execution-secret-at-least-32-bytes"
)
TRANSFER_CONTEXT = {
    "amount": 25_000,
    "account_verified": True,
}


@pytest.fixture
def sdk_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("DECAUSTRUM_API_KEY", TEST_API_KEY)
    monkeypatch.setenv(
        "DECAUSTRUM_ADMIN_API_KEY",
        TEST_ADMIN_API_KEY,
    )
    monkeypatch.setenv(
        "DECAUSTRUM_EXECUTION_GRANT_SECRET",
        TEST_EXECUTION_SECRET,
    )
    store = EvidenceStore(tmp_path / "sdk-integration.db")
    store.initialize()
    bootstrap_default_project(store=store, api_key=TEST_API_KEY)
    store.seed_project_policies(
        project_id=DEFAULT_PROJECT_ID,
        policies=load_policies(POLICIES_DIRECTORY),
        seeded_at=datetime.now(timezone.utc),
    )
    app.dependency_overrides[get_evidence_store] = lambda: store
    http_client = TestClient(app)
    sdk = DecAustrumClient(
        api_key=TEST_API_KEY,
        base_url="http://testserver",
        http_client=http_client,
    )

    yield sdk, store

    http_client.close()
    app.dependency_overrides.clear()


def test_sdk_runs_allow_operation_against_real_api(sdk_environment):
    sdk, _ = sdk_environment
    guard = DecAustrumGuard(sdk)
    calls = 0

    def refund() -> str:
        nonlocal calls
        calls += 1
        return "refund-completed"

    result = guard.execute(
        agent="support-agent",
        action="refund_payment",
        context={"amount": 300},
        operation=refund,
        idempotency_key="sdk-allow-refund",
    )

    assert result.value == "refund-completed"
    assert result.authorization is not None
    assert result.authorization.allowed is True
    assert result.authorization.project_id == DEFAULT_PROJECT_ID
    assert calls == 1


def test_sdk_blocks_denied_operation_against_real_api(sdk_environment):
    sdk, _ = sdk_environment
    guard = DecAustrumGuard(sdk)
    calls = 0

    def transfer() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(ActionDeniedError) as captured:
        guard.execute(
            agent="finance-agent",
            action="bank_transfer",
            context={
                "amount": 5_000,
                "account_verified": False,
            },
            operation=transfer,
        )

    assert captured.value.decision.policy == "unverified-account"
    assert calls == 0


def test_sdk_closes_real_approval_and_execution_flow(sdk_environment):
    sdk, _ = sdk_environment
    guard = DecAustrumGuard(sdk)
    calls = 0

    def transfer() -> str:
        nonlocal calls
        calls += 1
        return "transfer-completed"

    with pytest.raises(ApprovalRequiredError) as captured:
        guard.execute(
            agent="finance-agent",
            action="bank_transfer",
            context=TRANSFER_CONTEXT,
            operation=transfer,
            idempotency_key="sdk-approved-transfer",
        )

    decision = captured.value.decision
    assert calls == 0
    assert decision.requires_approval is True
    assert sdk.get_decision(decision.decision_id) == decision

    pending = sdk.get_approval(decision.decision_id)
    assert pending.status == "PENDING"
    page = sdk.list_approvals(status="PENDING")
    assert page.total == 1
    assert page.items == (pending,)

    grant = sdk.approve(
        decision.decision_id,
        resolved_by="security-reviewer",
        reason="Transfer evidence reviewed.",
    )
    assert grant.status == "APPROVED"
    assert grant.execution_grant.startswith("rgt_exec_v1.")
    assert grant.grant_expires_at > grant.resolved_at

    result = guard.execute_approved(
        execution_grant=grant.execution_grant,
        agent="finance-agent",
        action="bank_transfer",
        context=TRANSFER_CONTEXT,
        consumed_by="finance-runtime",
        operation=transfer,
    )

    assert result.value == "transfer-completed"
    assert result.consumption is not None
    assert result.consumption.decision_id == decision.decision_id
    assert result.consumption.grant_id == grant.grant_id
    assert calls == 1

    with pytest.raises(ConflictError) as replay:
        guard.execute_approved(
            execution_grant=grant.execution_grant,
            agent="finance-agent",
            action="bank_transfer",
            context=TRANSFER_CONTEXT,
            consumed_by="finance-runtime",
            operation=transfer,
        )

    assert replay.value.code == "execution_grant_already_consumed"
    assert calls == 1


def test_sdk_changed_context_cannot_run_and_does_not_consume_grant(
    sdk_environment,
):
    sdk, _ = sdk_environment
    decision = sdk.authorize(
        agent="finance-agent",
        action="bank_transfer",
        context=TRANSFER_CONTEXT,
    )
    grant = sdk.approve(
        decision.decision_id,
        resolved_by="security-reviewer",
    )
    guard = DecAustrumGuard(sdk)
    calls = 0

    def transfer() -> str:
        nonlocal calls
        calls += 1
        return "completed"

    with pytest.raises(ConflictError) as mismatch:
        guard.execute_approved(
            execution_grant=grant.execution_grant,
            agent="finance-agent",
            action="bank_transfer",
            context={
                "amount": 30_000,
                "account_verified": True,
            },
            consumed_by="finance-runtime",
            operation=transfer,
        )

    assert mismatch.value.code == "execution_grant_mismatch"
    assert calls == 0

    valid = guard.execute_approved(
        execution_grant=grant.execution_grant,
        agent="finance-agent",
        action="bank_transfer",
        context=TRANSFER_CONTEXT,
        consumed_by="finance-runtime",
        operation=transfer,
    )
    assert valid.value == "completed"
    assert calls == 1


def test_sdk_rejection_is_terminal_and_polling_returns_it(sdk_environment):
    sdk, _ = sdk_environment
    decision = sdk.authorize(
        agent="finance-agent",
        action="bank_transfer",
        context=TRANSFER_CONTEXT,
    )

    rejected = sdk.reject(
        decision.decision_id,
        resolved_by="security-reviewer",
        reason="Transfer not justified.",
    )
    polled = sdk.wait_for_approval(
        decision.decision_id,
        timeout=0.1,
        poll_interval=0.01,
    )

    assert rejected.status == "REJECTED"
    assert polled == rejected


def test_sdk_authorization_idempotency_uses_real_backend(sdk_environment):
    sdk, _ = sdk_environment
    first = sdk.authorize(
        agent="support-agent",
        action="refund_payment",
        context={"amount": 300},
        idempotency_key="sdk-idempotency-key",
    )
    second = sdk.authorize(
        agent="support-agent",
        action="refund_payment",
        context={"amount": 300},
        idempotency_key="sdk-idempotency-key",
    )

    assert second == first


def test_sdk_exposes_authentication_error_and_request_id(sdk_environment):
    _, _ = sdk_environment
    http_client = TestClient(app)
    invalid_sdk = DecAustrumClient(
        api_key="invalid-project-key",
        base_url="http://testserver",
        http_client=http_client,
    )
    try:
        with pytest.raises(AuthenticationError) as captured:
            invalid_sdk.authorize(
                agent="support-agent",
                action="refund_payment",
                context={"amount": 300},
            )
    finally:
        http_client.close()

    assert captured.value.code == "invalid_api_key"
    assert captured.value.request_id is not None


def test_async_sdk_and_guard_integrate_with_real_asgi_api(
    sdk_environment,
):
    _, _ = sdk_environment

    async def run_test():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
        ) as http_client:
            client = AsyncDecAustrumClient(
                api_key=TEST_API_KEY,
                base_url="http://testserver",
                http_client=http_client,
            )
            guard = AsyncDecAustrumGuard(client)
            calls = 0

            async def transfer() -> str:
                nonlocal calls
                calls += 1
                return "async-transfer-completed"

            with pytest.raises(ApprovalRequiredError) as pending:
                await guard.execute(
                    agent="finance-agent",
                    action="bank_transfer",
                    context=TRANSFER_CONTEXT,
                    operation=transfer,
                    idempotency_key="async-sdk-transfer",
                )

            assert calls == 0
            grant = await client.approve(
                pending.value.decision.decision_id,
                resolved_by="async-security-reviewer",
            )
            result = await guard.execute_approved(
                execution_grant=grant.execution_grant,
                agent="finance-agent",
                action="bank_transfer",
                context=TRANSFER_CONTEXT,
                consumed_by="async-finance-runtime",
                operation=transfer,
            )
            return result, calls

    result, calls = asyncio.run(run_test())

    assert result.value == "async-transfer-completed"
    assert result.authorization is None
    assert result.consumption is not None
    assert calls == 1

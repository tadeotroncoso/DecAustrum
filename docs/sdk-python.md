# Python SDK and real integration

The official Python SDK is an independently installable package under
`sdk/python`. It is a runtime client: application code can authorize an action,
handle approval, consume a one-time execution grant, and only then invoke the
real side effect. It does not import FastAPI, SQLite, policy files, or any
backend module.

## Installation

From the repository root:

```powershell
python -m pip install -e .\sdk\python
```

The package requires Python 3.11 or newer and depends only on `httpx`.

## Configuration

Pass configuration explicitly:

```python
from decaustrum import DecAustrumClient

client = DecAustrumClient(
    base_url="http://localhost:8000",
    api_key="project-api-key",
    timeout=10.0,
)
```

Or use `DecAustrumClient.from_environment()`, which reads:

- `DECAUSTRUM_API_KEY` (required);
- `DECAUSTRUM_BASE_URL` (defaults to `http://localhost:8000`).

The runnable approval example additionally reads
`DECAUSTRUM_REVIEWER_API_KEY`. Provision that key with role `REVIEWER`; the
general `from_environment()` constructor intentionally continues to use only
the runtime key.

Plaintext HTTP is accepted only for loopback hosts such as `localhost`,
`127.0.0.1`, and `::1`. Remote base URLs must use HTTPS. SDK requests never
follow redirects while carrying `X-API-Key`, including when an injected HTTPX
client has redirect following enabled.

The SDK sends `X-API-Key`, a versioned `User-Agent`, and a unique
`X-Request-ID` on every call. The request ID returned by DecAustrum is attached
to structured SDK exceptions for log correlation.

## Direct authorization

```python
decision = client.authorize(
    agent="support-agent",
    action="refund_payment",
    context={"amount": 300},
    idempotency_key="refund-order-42",
)

if decision.allowed:
    print("The action may run")
elif decision.denied:
    print(decision.reason)
else:
    print("Human approval is required", decision.decision_id)
```

The returned `AuthorizationDecision` contains typed UUIDs and timestamps, the
winning policy and version, evidence, the full policy trace, and convenience
properties for the three possible outcomes.

Supply a stable idempotency key from the business request. Reusing it with the
same agent, action, and context returns the original decision; reusing it for a
different request raises `ConflictError`.

## Enforcing a real operation

`DecAustrumGuard` couples authorization to a zero-argument callback. The callback
is not called after `DENY`, while approval is pending, or when grant validation
or consumption fails.

```python
from decaustrum import (
    ActionDeniedError,
    ApprovalRequiredError,
    DecAustrumGuard,
)

guard = DecAustrumGuard(client)

try:
    result = guard.execute(
        agent="finance-agent",
        action="bank_transfer",
        context={
            "amount": 25_000,
            "account_verified": True,
        },
        operation=lambda: bank.transfer(25_000),
        idempotency_key="transfer-42",
    )
except ActionDeniedError as exc:
    logger.warning("transfer denied: %s", exc.decision.reason)
except ApprovalRequiredError as exc:
    queue_for_review(exc.decision.decision_id)
```

Keep the business callback small and make it idempotent where possible.
DecAustrum decides whether execution is authorized; it cannot roll back an
external side effect after the callback starts.

## Closed approval flow

The reviewer resolves the pending request with a separate `REVIEWER` API key.
The runtime key cannot resolve its own request, and the reviewer identity is
derived by the server from the authenticated key. Approval returns the only
plaintext copy of a short-lived execution grant:

```python
reviewer = DecAustrumClient(
    base_url="https://decaustrum.internal",
    api_key=reviewer_api_key,
)

grant = reviewer.approve(
    decision_id,
    reason="Evidence reviewed.",
)
```

Transfer that bearer credential to the trusted execution runtime without
logging or persisting it. The SDK excludes it from the model representation.
The runtime consumes it against the exact original request before executing:

```python
result = guard.execute_approved(
    execution_grant=grant.execution_grant,
    agent="finance-agent",
    action="bank_transfer",
    context={
        "amount": 25_000,
        "account_verified": True,
    },
    consumed_by="finance-runtime",
    operation=lambda: bank.transfer(25_000),
)
```

Consumption is atomic and one-time. A replay, changed context, expired grant,
invalid signature, or wrong project prevents the callback from running. The
grant is consumed before callback invocation; if the external operation then
fails, create a new authorization rather than replaying the credential.

`get_approval`, `list_approvals`, `reject`, and `wait_for_approval` support a
separate reviewer workflow. Polling returns terminal state but never recovers a
plaintext execution grant from storage.

## Async applications

`AsyncDecAustrumClient` and `AsyncDecAustrumGuard` expose the same contracts:

```python
from decaustrum import AsyncDecAustrumClient, AsyncDecAustrumGuard

async with AsyncDecAustrumClient(
    base_url="https://decaustrum.internal",
    api_key="project-api-key",
) as client:
    guard = AsyncDecAustrumGuard(client)
    result = await guard.execute(
        agent="support-agent",
        action="refund_payment",
        context={"amount": 300},
        operation=perform_refund,
    )
```

The async callback must return an awaitable.

## Error handling

All SDK exceptions inherit from `DecAustrumError`:

| Exception | Meaning |
|---|---|
| `AuthenticationError` | Invalid or unauthorized project key |
| `NotFoundError` | Decision or approval not visible to this project |
| `ConflictError` | Idempotency or lifecycle conflict, including grant replay |
| `ValidationError` | Invalid request or incompatible policy context |
| `RateLimitError` | Configured API rate exceeded; includes `retry_after` |
| `ServerError` | DecAustrum returned a 5xx response |
| `DecAustrumTransportError` | Connection or timeout failure |
| `DecAustrumProtocolError` | Success response did not match the SDK contract |
| `ActionDeniedError` | Guard blocked a policy-denied operation |
| `ApprovalRequiredError` | Guard deferred execution for human review |

API errors expose `status_code`, `code`, `message`, `request_id`, `details`,
and `retry_after`. Do not retry grant consumption blindly after an ambiguous
network failure: query evidence and re-authorize if the outcome cannot be
established.

## Local end-to-end example

After starting DecAustrum with the local development environment, run:

```powershell
python .\sdk\python\examples\protected_bank_transfer.py
```

The example goes through real HTTP client code and the complete backend state
machine. Set `DECAUSTRUM_API_KEY` to a `RUNTIME` key and
`DECAUSTRUM_REVIEWER_API_KEY` to a separate `REVIEWER` key. The automated
integration suite runs the same path against the FastAPI ASGI application and
asserts that the business callback executes exactly once.

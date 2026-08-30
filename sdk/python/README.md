# RegTrace Python SDK

Typed Python client for the RegTrace runtime API. The SDK is intentionally
independent from the FastAPI backend and depends only on `httpx`.

## Install from this repository

```powershell
python -m pip install -e .\sdk\python
```

## Authorize an action

```python
from regtrace import RegTraceClient

with RegTraceClient(
    base_url="http://localhost:8000",
    api_key="your-project-api-key",
) as client:
    decision = client.authorize(
        agent="finance-agent",
        action="bank_transfer",
        context={
            "amount": 25_000,
            "account_verified": True,
        },
        idempotency_key="transfer-42",
    )

print(decision.decision, decision.reason)
```

Use `RegTraceGuard` when the business operation must only run after RegTrace
has authorized it. See `docs/sdk-python.md` and
`examples/protected_bank_transfer.py` in the main repository for the complete
approval and one-time execution-grant flow.

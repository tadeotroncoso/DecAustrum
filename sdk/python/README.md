# DecAustrum Python SDK

Typed Python client for the DecAustrum runtime API. The SDK is intentionally
independent from the FastAPI backend and depends only on `httpx`.

## Install from this repository

```powershell
python -m pip install -e .\sdk\python
```

## Authorize an action

```python
from decaustrum import DecAustrumClient

with DecAustrumClient(
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

Use `DecAustrumGuard` when the business operation must only run after DecAustrum
has authorized it. See the [SDK integration guide](../../docs/sdk-python.md) and
[protected bank transfer example](examples/protected_bank_transfer.py) for the
complete approval and one-time execution-grant flow.

Remote base URLs must use HTTPS; plaintext HTTP is accepted only for local
loopback development. Approval and rejection require a separate project API key
with the `REVIEWER` role. Runtime keys authorize and consume grants but cannot
approve their own requests.

## License and support

The DecAustrum SDK is source-available under the
[DecAustrum Portfolio Evaluation License](LICENSE), not an open-source license.
It may be installed and run for portfolio or commercial-license evaluation,
but production use, redistribution, and commercial exploitation require a
separate written agreement.

The SDK is provided without support, maintenance, warranty, or service-level
commitment. Its HTTPX dependency remains subject to HTTPX's BSD-3-Clause
license and is not bundled into the SDK wheel. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the audited SDK dependency
licenses.

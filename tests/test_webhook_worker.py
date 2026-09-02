import sys
from unittest.mock import Mock

import pytest

import app.webhook_worker as worker_module
from app.webhook_models import WebhookDispatchSummary


def test_worker_once_processes_one_bounded_batch(monkeypatch):
    calls = []
    expected = WebhookDispatchSummary(
        claimed=2,
        delivered=1,
        retry_scheduled=1,
        dead_lettered=0,
        cancelled=0,
    )

    def fake_dispatch(**kwargs):
        calls.append(kwargs)
        return expected

    monkeypatch.setattr(
        worker_module,
        "dispatch_pending_webhooks",
        fake_dispatch,
    )
    store = object()
    transport = object()

    result = worker_module.run_webhook_worker(
        store=store,
        transport=transport,
        master_secret="m" * 32,
        batch_size=25,
        once=True,
        sleep=lambda _seconds: pytest.fail(
            "one-shot worker must not sleep"
        ),
    )

    assert result == expected
    assert calls == [
        {
            "store": store,
            "transport": transport,
            "master_secret": "m" * 32,
            "limit": 25,
        }
    ]


@pytest.mark.parametrize(
    ("batch_size", "poll_interval"),
    [(0, 2.0), (101, 2.0), (20, 0), (20, -1)],
)
def test_worker_rejects_invalid_operational_settings(
    batch_size,
    poll_interval,
):
    with pytest.raises(ValueError):
        worker_module.run_webhook_worker(
            store=object(),
            transport=object(),
            master_secret="m" * 32,
            batch_size=batch_size,
            poll_interval_seconds=poll_interval,
            once=True,
        )


def test_worker_rejects_reused_master_secret_before_opening_storage(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["decaustrum-webhook-worker", "--once"])
    monkeypatch.setenv("DECAUSTRUM_ENVIRONMENT", "test")
    monkeypatch.setenv("DECAUSTRUM_TRUSTED_HOSTS", "localhost")
    monkeypatch.setenv("DECAUSTRUM_WEBHOOK_MASTER_SECRET", "s" * 32)
    monkeypatch.setenv("DECAUSTRUM_API_KEY", "s" * 32)
    store_factory = Mock()
    dispatch = Mock()
    monkeypatch.setattr(worker_module, "EvidenceStore", store_factory)
    monkeypatch.setattr(worker_module, "run_webhook_worker", dispatch)
    monkeypatch.setattr(worker_module, "configure_json_logging", Mock())

    with pytest.raises(SystemExit) as error:
        worker_module.main()

    assert error.value.code == 1
    store_factory.assert_not_called()
    dispatch.assert_not_called()

import argparse
import logging
import os
import time
from collections.abc import Callable

from app.dependencies import DATABASE_PATH
from app.evidence_store import EvidenceStore
from app.observability import configure_json_logging
from app.runtime_config import RuntimeSettings
from app.security import get_configured_webhook_master_secret
from app.services.webhooks import dispatch_pending_webhooks
from app.webhook_models import WebhookDispatchSummary
from app.webhooks import UrllibWebhookTransport, WebhookTransport


LOGGER = logging.getLogger("decaustrum.webhook_worker")


def run_webhook_worker(
    *,
    store: EvidenceStore,
    transport: WebhookTransport,
    master_secret: str,
    batch_size: int = 20,
    poll_interval_seconds: float = 2.0,
    once: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> WebhookDispatchSummary:
    if batch_size < 1 or batch_size > 100:
        raise ValueError(
            "Webhook worker batch size must be between 1 and 100."
        )

    if poll_interval_seconds <= 0:
        raise ValueError(
            "Webhook worker poll interval must be positive."
        )

    last_summary = WebhookDispatchSummary(
        claimed=0,
        delivered=0,
        retry_scheduled=0,
        dead_lettered=0,
        cancelled=0,
    )

    while True:
        last_summary = dispatch_pending_webhooks(
            store=store,
            transport=transport,
            master_secret=master_secret,
            limit=batch_size,
        )

        if last_summary.claimed:
            LOGGER.info(
                "webhook_batch_processed",
                extra=last_summary.model_dump(),
            )

        if once:
            return last_summary

        if last_summary.claimed < batch_size:
            sleep(poll_interval_seconds)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Deliver due DecAustrum webhook outbox records."
        )
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process one bounded batch and exit.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=20,
        choices=range(1, 101),
        metavar="1-100",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=2.0,
        help="Seconds to wait when no full batch is available.",
    )

    return parser


def main() -> None:
    arguments = build_argument_parser().parse_args()
    settings = RuntimeSettings.from_environment(os.environ)
    configure_json_logging(
        settings.log_level,
    )
    store = EvidenceStore(DATABASE_PATH)
    store.initialize()

    try:
        run_webhook_worker(
            store=store,
            transport=UrllibWebhookTransport(),
            master_secret=(
                get_configured_webhook_master_secret()
            ),
            batch_size=arguments.batch_size,
            poll_interval_seconds=arguments.poll_interval,
            once=arguments.once,
        )
    except KeyboardInterrupt:
        LOGGER.info("webhook_worker_stopped")
    except Exception:
        LOGGER.exception("webhook_worker_failed")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

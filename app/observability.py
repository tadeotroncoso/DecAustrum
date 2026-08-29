import json
import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


REGTRACE_VERSION = "0.1.0"
HTTP_DURATION_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
)


def _escape_label(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def _labels(**values: str) -> str:
    if not values:
        return ""

    content = ",".join(
        f'{name}="{_escape_label(value)}"'
        for name, value in sorted(values.items())
    )
    return "{" + content + "}"


def _number(value: float | int) -> str:
    if isinstance(value, int):
        return str(value)

    return format(value, ".12g")


@dataclass
class _Histogram:
    count: int = 0
    total: float = 0.0
    bucket_counts: list[int] = field(
        default_factory=lambda: [0] * len(HTTP_DURATION_BUCKETS)
    )

    def observe(self, value: float) -> None:
        self.count += 1
        self.total += value

        for index, boundary in enumerate(HTTP_DURATION_BUCKETS):
            if value <= boundary:
                self.bucket_counts[index] += 1


class MetricsRegistry:
    """Small bounded-cardinality Prometheus registry for RegTrace."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._started_at = time.time()
        self._in_flight = 0
        self._ready = 0
        self._http_requests: dict[
            tuple[str, str, str],
            int,
        ] = defaultdict(int)
        self._http_durations: dict[
            tuple[str, str],
            _Histogram,
        ] = {}
        self._security_events: dict[str, int] = defaultdict(int)
        self._authorization_decisions: dict[str, int] = (
            defaultdict(int)
        )

    def request_started(self) -> None:
        with self._lock:
            self._in_flight += 1

    def request_finished(
        self,
        *,
        method: str,
        route: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        status = str(status_code)
        key = (method, route, status)
        duration_key = (method, route)

        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
            self._http_requests[key] += 1
            histogram = self._http_durations.setdefault(
                duration_key,
                _Histogram(),
            )
            histogram.observe(duration_seconds)

    def record_security_event(self, event: str) -> None:
        with self._lock:
            self._security_events[event] += 1

    def record_authorization_decision(self, decision: str) -> None:
        with self._lock:
            self._authorization_decisions[decision] += 1

    def set_ready(self, ready: bool) -> None:
        with self._lock:
            self._ready = 1 if ready else 0

    def reset(self) -> None:
        with self._lock:
            self._started_at = time.time()
            self._in_flight = 0
            self._ready = 0
            self._http_requests.clear()
            self._http_durations.clear()
            self._security_events.clear()
            self._authorization_decisions.clear()

    def render_prometheus(self) -> str:
        with self._lock:
            started_at = self._started_at
            in_flight = self._in_flight
            ready = self._ready
            requests = dict(self._http_requests)
            durations = {
                key: _Histogram(
                    count=value.count,
                    total=value.total,
                    bucket_counts=list(value.bucket_counts),
                )
                for key, value in self._http_durations.items()
            }
            security_events = dict(self._security_events)
            authorization_decisions = dict(
                self._authorization_decisions
            )

        lines = [
            "# HELP regtrace_build_info RegTrace build information.",
            "# TYPE regtrace_build_info gauge",
            (
                "regtrace_build_info"
                f'{_labels(version=REGTRACE_VERSION)} 1'
            ),
            (
                "# HELP regtrace_process_start_time_seconds "
                "Process start time in Unix seconds."
            ),
            "# TYPE regtrace_process_start_time_seconds gauge",
            (
                "regtrace_process_start_time_seconds "
                f"{_number(started_at)}"
            ),
            (
                "# HELP regtrace_http_in_flight_requests "
                "Current in-flight HTTP requests."
            ),
            "# TYPE regtrace_http_in_flight_requests gauge",
            f"regtrace_http_in_flight_requests {in_flight}",
            (
                "# HELP regtrace_ready Whether the API is ready to "
                "serve traffic."
            ),
            "# TYPE regtrace_ready gauge",
            f"regtrace_ready {ready}",
            (
                "# HELP regtrace_http_requests_total Total HTTP "
                "requests."
            ),
            "# TYPE regtrace_http_requests_total counter",
        ]

        for (method, route, status), value in sorted(requests.items()):
            lines.append(
                "regtrace_http_requests_total"
                f"{_labels(method=method, route=route, status=status)} "
                f"{value}"
            )

        lines.extend(
            [
                (
                    "# HELP regtrace_http_request_duration_seconds "
                    "HTTP request duration in seconds."
                ),
                (
                    "# TYPE regtrace_http_request_duration_seconds "
                    "histogram"
                ),
            ]
        )

        for (method, route), histogram in sorted(durations.items()):
            for boundary, count in zip(
                HTTP_DURATION_BUCKETS,
                histogram.bucket_counts,
                strict=True,
            ):
                lines.append(
                    "regtrace_http_request_duration_seconds_bucket"
                    f"{_labels(method=method, route=route, le=str(boundary))} "
                    f"{count}"
                )

            lines.append(
                "regtrace_http_request_duration_seconds_bucket"
                f"{_labels(method=method, route=route, le='+Inf')} "
                f"{histogram.count}"
            )
            lines.append(
                "regtrace_http_request_duration_seconds_sum"
                f"{_labels(method=method, route=route)} "
                f"{_number(histogram.total)}"
            )
            lines.append(
                "regtrace_http_request_duration_seconds_count"
                f"{_labels(method=method, route=route)} "
                f"{histogram.count}"
            )

        lines.extend(
            [
                (
                    "# HELP regtrace_security_events_total Security "
                    "control events."
                ),
                "# TYPE regtrace_security_events_total counter",
            ]
        )

        for event, value in sorted(security_events.items()):
            lines.append(
                "regtrace_security_events_total"
                f"{_labels(event=event)} {value}"
            )

        lines.extend(
            [
                (
                    "# HELP regtrace_authorization_decisions_total "
                    "Authorization responses by decision."
                ),
                (
                    "# TYPE regtrace_authorization_decisions_total "
                    "counter"
                ),
            ]
        )

        for decision, value in sorted(
            authorization_decisions.items()
        ):
            lines.append(
                "regtrace_authorization_decisions_total"
                f"{_labels(decision=decision)} {value}"
            )

        return "\n".join(lines) + "\n"


class JsonLogFormatter(logging.Formatter):
    INCLUDED_FIELDS = (
        "request_id",
        "method",
        "route",
        "status_code",
        "duration_ms",
        "principal_type",
        "security_event",
        "claimed",
        "delivered",
        "retry_scheduled",
        "dead_lettered",
        "cancelled",
    )

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created,
                tz=timezone.utc,
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }

        for field_name in self.INCLUDED_FIELDS:
            value = getattr(record, field_name, None)

            if value is not None:
                payload[field_name] = value

        if record.exc_info is not None:
            exception_type = record.exc_info[0]
            payload["exception_type"] = exception_type.__name__

        return json.dumps(
            payload,
            sort_keys=True,
            ensure_ascii=False,
        )


def configure_json_logging(level: str = "INFO") -> None:
    regtrace_logger = logging.getLogger("regtrace")
    handler = next(
        (
            item
            for item in regtrace_logger.handlers
            if getattr(item, "_regtrace_json_handler", False)
        ),
        None,
    )

    if handler is None:
        handler = logging.StreamHandler()
        handler._regtrace_json_handler = True  # type: ignore[attr-defined]
        regtrace_logger.addHandler(handler)

    handler.setFormatter(JsonLogFormatter())
    regtrace_logger.setLevel(level)
    regtrace_logger.propagate = False

    # RegTrace emits its own access records without raw paths, query
    # strings, headers, or bodies.
    logging.getLogger("uvicorn.access").disabled = True


__all__ = [
    "JsonLogFormatter",
    "MetricsRegistry",
    "REGTRACE_VERSION",
    "configure_json_logging",
]

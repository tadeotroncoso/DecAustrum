import json
import logging
import sys

from app.observability import JsonLogFormatter, MetricsRegistry


def test_metrics_registry_renders_prometheus_metrics():
    registry = MetricsRegistry()
    registry.set_ready(True)
    registry.request_started()
    registry.request_finished(
        method="POST",
        route="/v1/authorize",
        status_code=200,
        duration_seconds=0.08,
    )
    registry.record_security_event("authentication_failed")
    registry.record_authorization_decision("DENY")

    rendered = registry.render_prometheus()

    assert "# TYPE decaustrum_http_requests_total counter" in rendered
    assert (
        'decaustrum_http_requests_total{method="POST",'
        'route="/v1/authorize",status="200"} 1'
    ) in rendered
    assert (
        'decaustrum_http_request_duration_seconds_bucket{le="0.1",'
        'method="POST",route="/v1/authorize"} 1'
    ) in rendered
    assert "decaustrum_http_in_flight_requests 0" in rendered
    assert "decaustrum_ready 1" in rendered
    assert (
        'decaustrum_security_events_total{event="authentication_failed"} 1'
    ) in rendered
    assert (
        'decaustrum_authorization_decisions_total{decision="DENY"} 1'
    ) in rendered
    assert rendered.endswith("\n")


def test_metrics_registry_resets_all_runtime_values():
    registry = MetricsRegistry()
    registry.set_ready(True)
    registry.request_started()
    registry.request_finished(
        method="GET",
        route="/health",
        status_code=200,
        duration_seconds=0.01,
    )

    registry.reset()
    rendered = registry.render_prometheus()

    assert "decaustrum_ready 0" in rendered
    assert "decaustrum_http_in_flight_requests 0" in rendered
    assert 'route="/health"' not in rendered


def test_prometheus_labels_are_escaped():
    registry = MetricsRegistry()
    registry.record_security_event('quote"line\nslash\\')

    rendered = registry.render_prometheus()

    assert 'event="quote\\"line\\nslash\\\\"' in rendered


def test_json_log_formatter_emits_only_safe_allowlisted_fields():
    record = logging.LogRecord(
        name="decaustrum.http",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="http_request_completed",
        args=(),
        exc_info=None,
    )
    record.request_id = "request-123"
    record.method = "POST"
    record.route = "/v1/authorize"
    record.status_code = 200
    record.api_key = "must-not-appear"
    record.context = {"account": "must-not-appear"}

    payload = json.loads(JsonLogFormatter().format(record))

    assert payload["event"] == "http_request_completed"
    assert payload["request_id"] == "request-123"
    assert payload["route"] == "/v1/authorize"
    assert "api_key" not in payload
    assert "context" not in payload
    assert "must-not-appear" not in json.dumps(payload)


def test_json_log_formatter_reports_exception_type_not_message():
    try:
        raise ValueError("sensitive-value-must-not-be-logged")
    except ValueError:
        exception_info = sys.exc_info()

    record = logging.LogRecord(
        name="decaustrum.http",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="http_request_failed",
        args=(),
        exc_info=exception_info,
    )

    formatted = JsonLogFormatter().format(record)
    payload = json.loads(formatted)

    assert payload["exception_type"] == "ValueError"
    assert "sensitive-value-must-not-be-logged" not in formatted


def test_metrics_registry_groups_unknown_methods_with_bounded_storage():
    registry = MetricsRegistry()
    methods = [f"UNRECOGNIZED{index}" for index in range(256)]
    methods.extend(["", "get", "GET ", "OTHER", "non-ascii-\u00e9"])

    for method in methods:
        registry.request_started()
        registry.request_finished(
            method=method,
            route="/health",
            status_code=405,
            duration_seconds=0.25,
        )

    assert dict(registry._http_requests) == {
        ("OTHER", "/health", "405"): len(methods),
    }
    assert set(registry._http_durations) == {("OTHER", "/health")}
    histogram = registry._http_durations[("OTHER", "/health")]
    assert histogram.count == len(methods)
    assert histogram.total == len(methods) * 0.25
    assert histogram.bucket_counts[-1] == len(methods)

    rendered = registry.render_prometheus()
    assert "UNRECOGNIZED" not in rendered
    assert "non-ascii" not in rendered
    assert (
        'decaustrum_http_requests_total{method="OTHER",'
        f'route="/health",status="405"}} {len(methods)}'
    ) in rendered
    assert "decaustrum_http_in_flight_requests 0" in rendered


def test_metrics_registry_preserves_known_methods_and_statuses():
    registry = MetricsRegistry()
    methods = (
        "GET", "HEAD", "POST", "PUT", "DELETE",
        "CONNECT", "OPTIONS", "TRACE", "PATCH",
    )

    for method in methods:
        for status in (200, 405):
            registry.request_started()
            registry.request_finished(
                method=method,
                route="/health",
                status_code=status,
                duration_seconds=0.25,
            )

    assert dict(registry._http_requests) == {
        (method, "/health", str(status)): 1
        for method in methods
        for status in (200, 405)
    }
    assert set(registry._http_durations) == {
        (method, "/health") for method in methods
    }
    for histogram in registry._http_durations.values():
        assert histogram.count == 2
        assert histogram.total == 0.5
    assert 'method="OTHER"' not in registry.render_prometheus()

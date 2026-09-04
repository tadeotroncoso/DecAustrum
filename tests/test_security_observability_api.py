from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.api_keys import generate_project_api_key
from app.bootstrap import bootstrap_default_project
from app.dependencies import get_evidence_store
from app.evidence_store import EvidenceStore
from app.main import create_app
from app.policy_engine import POLICIES_DIRECTORY
from app.policy_loader import load_policies
from app.project_models import DEFAULT_PROJECT_ID
from app.runtime_config import RuntimeSettings


def build_settings(**overrides) -> RuntimeSettings:
    values = {
        "environment": "test",
        "trusted_hosts": ("testserver",),
        "cors_allowed_origins": (),
        "enforce_https": False,
        "expose_docs": True,
        "rate_limit_enabled": False,
        "max_request_body_bytes": 1_048_576,
        "rate_limit_window_seconds": 60,
        "authorization_rate_limit": 300,
        "tenant_rate_limit": 600,
        "admin_rate_limit": 300,
        "log_level": "INFO",
    }
    values.update(overrides)
    return RuntimeSettings(**values)


def test_responses_include_request_id_and_defensive_headers():
    client = TestClient(create_app(build_settings()))

    response = client.get(
        "/health",
        headers={"X-Request-ID": "caller-request-123"},
    )

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "caller-request-123"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["permissions-policy"]


def test_invalid_request_id_is_replaced():
    client = TestClient(create_app(build_settings()))

    response = client.get(
        "/health",
        headers={"X-Request-ID": "invalid request id"},
    )

    generated = response.headers["x-request-id"]
    assert generated != "invalid request id"
    assert len(generated) == 36


def test_untrusted_host_is_rejected_before_routing():
    client = TestClient(create_app(build_settings()))

    response = client.get(
        "/health",
        headers={"Host": "attacker.example"},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_host"


def test_https_enforcement_and_hsts():
    application = create_app(
        build_settings(enforce_https=True)
    )

    insecure = TestClient(application).get("/health")
    secure = TestClient(
        application,
        base_url="https://testserver",
    ).get("/health")

    assert insecure.status_code == 400
    assert insecure.json()["detail"]["code"] == "https_required"
    assert secure.status_code == 200
    assert secure.headers["strict-transport-security"].startswith(
        "max-age=31536000"
    )


def test_allowed_cors_origin_receives_exact_origin():
    client = TestClient(
        create_app(
            build_settings(
                cors_allowed_origins=(
                    "https://console.example.com",
                )
            )
        )
    )

    response = client.get(
        "/health",
        headers={"Origin": "https://console.example.com"},
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == (
        "https://console.example.com"
    )
    assert "x-request-id" in response.headers[
        "access-control-expose-headers"
    ].lower()
    assert "Origin" in response.headers["vary"]


def test_disallowed_cors_origin_is_rejected():
    client = TestClient(
        create_app(
            build_settings(
                cors_allowed_origins=(
                    "https://console.example.com",
                )
            )
        )
    )

    response = client.get(
        "/health",
        headers={"Origin": "https://attacker.example"},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == (
        "cors_origin_denied"
    )


def test_cors_preflight_is_strict_and_bounded():
    client = TestClient(
        create_app(
            build_settings(
                cors_allowed_origins=(
                    "https://console.example.com",
                )
            )
        )
    )
    headers = {
        "Origin": "https://console.example.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": (
            "Content-Type, X-API-Key, Idempotency-Key"
        ),
    }

    allowed = client.options("/v1/authorize", headers=headers)
    denied = client.options(
        "/v1/authorize",
        headers={
            **headers,
            "Access-Control-Request-Headers": "X-Internal-Secret",
        },
    )

    assert allowed.status_code == 204
    assert allowed.headers["access-control-allow-origin"] == (
        "https://console.example.com"
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == (
        "cors_preflight_denied"
    )


def test_oversized_request_is_rejected_before_parsing():
    client = TestClient(
        create_app(build_settings(max_request_body_bytes=32))
    )

    response = client.post(
        "/v1/authorize",
        content=b"x" * 33,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == (
        "request_body_too_large"
    )


def test_v1_write_body_must_use_json_content_type():
    client = TestClient(create_app(build_settings()))

    response = client.post(
        "/v1/authorize",
        content=b"{}",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 415
    assert response.json()["detail"]["code"] == (
        "unsupported_content_type"
    )


def test_malformed_content_length_is_rejected():
    client = TestClient(create_app(build_settings()))

    response = client.post(
        "/v1/authorize",
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": "invalid",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == (
        "invalid_content_length"
    )


def test_rate_limit_isolated_clients_and_blocks_same_origin_spraying():
    application = create_app(
        build_settings(
            rate_limit_enabled=True,
            tenant_rate_limit=1,
        )
    )
    application.add_api_route(
        "/v1/ping",
        lambda: {"status": "ok"},
        methods=["GET"],
    )
    client = TestClient(
        application,
        client=("192.0.2.10", 50_000),
    )
    other_client = TestClient(
        application,
        client=("192.0.2.11", 50_000),
    )

    first = client.get(
        "/v1/ping",
        headers={"X-API-Key": "first-key"},
    )
    denied = client.get(
        "/v1/ping",
        headers={"X-API-Key": "first-key"},
    )
    sprayed_key = client.get(
        "/v1/ping",
        headers={"X-API-Key": "sprayed-key"},
    )
    other_key = other_client.get(
        "/v1/ping",
        headers={"X-API-Key": "second-key"},
    )

    assert first.status_code == 200
    assert first.headers["ratelimit-remaining"] == "0"
    assert denied.status_code == 429
    assert denied.headers["retry-after"]
    assert denied.json()["detail"]["code"] == "rate_limit_exceeded"
    assert sprayed_key.status_code == 429
    assert other_key.status_code == 200


def test_unhandled_exception_returns_safe_error():
    application = create_app(build_settings())

    def fail():
        raise ValueError("internal implementation detail")

    application.add_api_route(
        "/v1/fail",
        fail,
        methods=["GET"],
    )
    response = TestClient(application).get("/v1/fail")

    assert response.status_code == 500
    assert response.json() == {
        "detail": {
            "code": "internal_server_error",
            "message": "An unexpected error occurred.",
        }
    }
    assert "implementation detail" not in response.text


def test_validation_errors_do_not_echo_request_values():
    application = create_app(build_settings())

    class Payload(BaseModel):
        count: int

    def validate_payload(payload: Payload):
        return payload

    application.add_api_route(
        "/v1/validate",
        validate_payload,
        methods=["POST"],
    )
    response = TestClient(application).post(
        "/v1/validate",
        json={"count": "sensitive-request-value"},
    )

    assert response.status_code == 422
    assert "sensitive-request-value" not in response.text
    assert set(response.json()["detail"][0]) == {
        "type",
        "loc",
        "msg",
    }


def test_metrics_use_route_templates_not_resource_ids():
    application = create_app(build_settings())

    application.add_api_route(
        "/items/{item_id}",
        lambda item_id: {"item_id": item_id},
        methods=["GET"],
    )
    item_id = str(uuid4())

    response = TestClient(application).get(f"/items/{item_id}")
    rendered = application.state.metrics_registry.render_prometheus()

    assert response.status_code == 200
    assert 'route="/items/{item_id}"' in rendered
    assert item_id not in rendered


def test_health_readiness_reports_store_state():
    application = create_app(build_settings())

    class ReadyStore:
        def check_readiness(self):
            return True

    application.dependency_overrides[get_evidence_store] = ReadyStore
    client = TestClient(application)

    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.status_code == 200
    assert ready.status_code == 200
    assert ready.json() == {"status": "ok"}
    assert "decaustrum_ready 1" in (
        application.state.metrics_registry.render_prometheus()
    )


def test_health_readiness_hides_storage_failure_details():
    application = create_app(build_settings())

    class FailingStore:
        def check_readiness(self):
            raise RuntimeError("database path must remain private")

    application.dependency_overrides[get_evidence_store] = FailingStore

    response = TestClient(application).get("/health/ready")

    assert response.status_code == 503
    assert response.json() == {"status": "unavailable"}
    assert "database path" not in response.text


def test_metrics_require_admin_authentication(monkeypatch):
    admin_key = "admin-observability-key"
    monkeypatch.setenv("DECAUSTRUM_ADMIN_API_KEY", admin_key)
    application = create_app(build_settings())
    client = TestClient(application)
    client.get("/health")

    missing = client.get("/metrics")
    wrong = client.get(
        "/metrics",
        headers={"X-Admin-API-Key": "wrong"},
    )
    allowed = client.get(
        "/metrics",
        headers={"X-Admin-API-Key": admin_key},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert allowed.status_code == 200
    assert allowed.headers["content-type"] == (
        "text/plain; version=0.0.4; charset=utf-8"
    )
    assert "decaustrum_http_requests_total" in allowed.text
    assert admin_key not in allowed.text


def test_authorization_decision_is_counted_without_tenant_labels(
    tmp_path,
    monkeypatch,
):
    api_key = generate_project_api_key()
    admin_key = "admin-observability-key"
    monkeypatch.setenv("DECAUSTRUM_ADMIN_API_KEY", admin_key)
    store = EvidenceStore(tmp_path / "decaustrum.db")
    store.initialize()
    bootstrap_default_project(store=store, api_key=api_key)
    store.seed_project_policies(
        project_id=DEFAULT_PROJECT_ID,
        policies=load_policies(POLICIES_DIRECTORY),
        seeded_at=datetime.now(timezone.utc),
    )
    application = create_app(build_settings())
    application.dependency_overrides[get_evidence_store] = lambda: store
    client = TestClient(application)

    authorization = client.post(
        "/v1/authorize",
        headers={"X-API-Key": api_key},
        json={
            "agent": "support-agent",
            "action": "refund_payment",
            "context": {"amount": 300},
        },
    )
    metrics = client.get(
        "/metrics",
        headers={"X-Admin-API-Key": admin_key},
    )

    assert authorization.status_code == 200
    assert (
        'decaustrum_authorization_decisions_total{decision="ALLOW"} 1'
        in metrics.text
    )
    assert api_key not in metrics.text
    assert str(DEFAULT_PROJECT_ID) not in metrics.text


def test_production_application_does_not_expose_api_docs():
    settings = RuntimeSettings(
        environment="production",
        trusted_hosts=("testserver",),
        enforce_https=True,
        expose_docs=False,
        rate_limit_enabled=False,
    )
    client = TestClient(
        create_app(settings),
        base_url="https://testserver",
    )

    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_unknown_http_methods_do_not_grow_health_metrics():
    application = create_app(build_settings(rate_limit_enabled=True))
    client = TestClient(application)

    try:
        for index in range(40):
            response = client.request(f"UNRECOGNIZED{index}", "/health")
            assert response.status_code == 405

        registry = application.state.metrics_registry
        assert dict(registry._http_requests) == {
            ("OTHER", "/health", "405"): 40,
        }
        assert set(registry._http_durations) == {("OTHER", "/health")}
        assert registry._http_durations[("OTHER", "/health")].count == 40
        assert "UNRECOGNIZED" not in registry.render_prometheus()

        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        assert registry._http_requests[("GET", "/health", "200")] == 1
        assert len(registry._http_requests) == 2
        assert len(registry._http_durations) == 2
    finally:
        client.close()


def test_unknown_http_methods_are_grouped_on_early_rejection():
    application = create_app(build_settings(rate_limit_enabled=True))
    client = TestClient(application)

    try:
        for index in range(40):
            response = client.request(
                f"UNRECOGNIZED{index}",
                f"/unmatched-{index}",
                headers={"Host": "untrusted.example"},
            )
            assert response.status_code == 400
            assert response.json()["detail"]["code"] == "invalid_host"

        registry = application.state.metrics_registry
        assert dict(registry._http_requests) == {
            ("OTHER", "unmatched", "400"): 40,
        }
        assert set(registry._http_durations) == {("OTHER", "unmatched")}
        rendered = registry.render_prometheus()
        assert "UNRECOGNIZED" not in rendered
        assert "/unmatched-" not in rendered
    finally:
        client.close()


def test_metric_method_grouping_does_not_change_custom_method_routing():
    application = create_app(build_settings())
    application.add_api_route(
        "/custom-method",
        lambda: {"status": "custom-handler"},
        methods=["CUSTOM"],
    )
    client = TestClient(application)

    try:
        response = client.request("CUSTOM", "/custom-method")
        assert response.status_code == 200
        assert response.json() == {"status": "custom-handler"}
        assert dict(application.state.metrics_registry._http_requests) == {
            ("OTHER", "/custom-method", "200"): 1,
        }
    finally:
        client.close()

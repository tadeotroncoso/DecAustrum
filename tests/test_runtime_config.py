import pytest

from app.runtime_config import (
    RuntimeConfigurationError,
    RuntimeSettings,
)


def test_runtime_settings_have_safe_local_defaults():
    settings = RuntimeSettings.from_environment({})

    assert settings.environment == "development"
    assert settings.trusted_hosts == (
        "localhost",
        "127.0.0.1",
        "::1",
        "testserver",
    )
    assert settings.cors_allowed_origins == ()
    assert settings.rate_limit_enabled is True
    assert settings.max_request_body_bytes == 1_048_576
    assert settings.approval_ttl_seconds == 86_400
    assert settings.execution_grant_ttl_seconds == 300


def test_runtime_settings_parse_explicit_environment():
    settings = RuntimeSettings.from_environment(
        {
            "DECAUSTRUM_ENVIRONMENT": "test",
            "DECAUSTRUM_TRUSTED_HOSTS": (
                "api.example.com,*.internal.example.com"
            ),
            "DECAUSTRUM_CORS_ALLOWED_ORIGINS": (
                "https://console.example.com"
            ),
            "DECAUSTRUM_ENFORCE_HTTPS": "yes",
            "DECAUSTRUM_EXPOSE_DOCS": "off",
            "DECAUSTRUM_RATE_LIMIT_ENABLED": "0",
            "DECAUSTRUM_MAX_REQUEST_BODY_BYTES": "2048",
            "DECAUSTRUM_RATE_LIMIT_WINDOW_SECONDS": "30",
            "DECAUSTRUM_AUTHORIZATION_RATE_LIMIT": "10",
            "DECAUSTRUM_TENANT_RATE_LIMIT": "20",
            "DECAUSTRUM_ADMIN_RATE_LIMIT": "5",
            "DECAUSTRUM_APPROVAL_TTL_SECONDS": "3600",
            "DECAUSTRUM_EXECUTION_GRANT_TTL_SECONDS": "120",
            "DECAUSTRUM_LOG_LEVEL": "warning",
        }
    )

    assert settings.trusted_hosts == (
        "api.example.com",
        "*.internal.example.com",
    )
    assert settings.cors_allowed_origins == (
        "https://console.example.com",
    )
    assert settings.enforce_https is True
    assert settings.expose_docs is False
    assert settings.rate_limit_enabled is False
    assert settings.max_request_body_bytes == 2048
    assert settings.rate_limit_window_seconds == 30
    assert settings.authorization_rate_limit == 10
    assert settings.tenant_rate_limit == 20
    assert settings.admin_rate_limit == 5
    assert settings.approval_ttl_seconds == 3600
    assert settings.execution_grant_ttl_seconds == 120
    assert settings.log_level == "WARNING"


def test_production_defaults_require_explicit_trusted_hosts():
    with pytest.raises(
        RuntimeConfigurationError,
        match="DECAUSTRUM_TRUSTED_HOSTS",
    ):
        RuntimeSettings.from_environment(
            {"DECAUSTRUM_ENVIRONMENT": "production"}
        )


def test_production_defaults_disable_docs_and_require_https():
    settings = RuntimeSettings.from_environment(
        {
            "DECAUSTRUM_ENVIRONMENT": "production",
            "DECAUSTRUM_TRUSTED_HOSTS": "api.example.com",
        }
    )

    assert settings.enforce_https is True
    assert settings.expose_docs is False


@pytest.mark.parametrize(
    "environment",
    [
        {"DECAUSTRUM_ENVIRONMENT": "staging"},
        {"DECAUSTRUM_RATE_LIMIT_ENABLED": "sometimes"},
        {"DECAUSTRUM_MAX_REQUEST_BODY_BYTES": "large"},
        {"DECAUSTRUM_MAX_REQUEST_BODY_BYTES": "0"},
        {"DECAUSTRUM_TRUSTED_HOSTS": "*"},
        {"DECAUSTRUM_TRUSTED_HOSTS": "*."},
        {"DECAUSTRUM_LOG_LEVEL": "LOUD"},
    ],
)
def test_runtime_settings_reject_invalid_values(environment):
    with pytest.raises(RuntimeConfigurationError):
        RuntimeSettings.from_environment(environment)


@pytest.mark.parametrize(
    "origin",
    [
        "*",
        "https://user@example.com",
        "https://example.com/path",
        "https://example.com?query=value",
        "not-an-origin",
        "http://remote.example.com",
    ],
)
def test_runtime_settings_reject_unsafe_cors_origins(origin):
    with pytest.raises(RuntimeConfigurationError):
        RuntimeSettings.from_environment(
            {"DECAUSTRUM_CORS_ALLOWED_ORIGINS": origin}
        )


def test_runtime_settings_allow_local_http_cors_in_development():
    settings = RuntimeSettings.from_environment(
        {
            "DECAUSTRUM_CORS_ALLOWED_ORIGINS": (
                "http://localhost:3000"
            )
        }
    )

    assert settings.cors_allowed_origins == (
        "http://localhost:3000",
    )


@pytest.mark.parametrize(
    ("project_key", "admin_key"),
    [
        ("short", "a" * 32),
        ("p" * 32, None),
        ("p" * 32, "short"),
        ("same-secret" * 4, "same-secret" * 4),
    ],
)
def test_production_rejects_weak_or_reused_secrets(
    project_key,
    admin_key,
):
    settings = RuntimeSettings(
        environment="production",
        trusted_hosts=("api.example.com",),
        enforce_https=True,
        expose_docs=False,
    )

    with pytest.raises(RuntimeConfigurationError):
        settings.validate_secrets(
            project_api_key=project_key,
            admin_api_key=admin_key,
            execution_grant_secret="grant-" + "g" * 32,
        )


def test_production_accepts_distinct_strong_secrets():
    settings = RuntimeSettings(
        environment="production",
        trusted_hosts=("api.example.com",),
        enforce_https=True,
        expose_docs=False,
    )

    settings.validate_secrets(
        project_api_key="project-" + "p" * 32,
        admin_api_key="admin-" + "a" * 32,
        execution_grant_secret="grant-" + "g" * 32,
    )


@pytest.mark.parametrize(
    "environment",
    [
        {"DECAUSTRUM_APPROVAL_TTL_SECONDS": "59"},
        {"DECAUSTRUM_APPROVAL_TTL_SECONDS": "2592001"},
        {"DECAUSTRUM_EXECUTION_GRANT_TTL_SECONDS": "29"},
        {"DECAUSTRUM_EXECUTION_GRANT_TTL_SECONDS": "3601"},
    ],
)
def test_runtime_settings_reject_invalid_lifecycle_ttls(environment):
    with pytest.raises(RuntimeConfigurationError):
        RuntimeSettings.from_environment(environment)


def test_production_requires_strong_distinct_execution_secret():
    settings = RuntimeSettings(
        environment="production",
        trusted_hosts=("api.example.com",),
        enforce_https=True,
        expose_docs=False,
    )

    with pytest.raises(RuntimeConfigurationError):
        settings.validate_secrets(
            project_api_key="project-" + "p" * 32,
            admin_api_key="admin-" + "a" * 32,
            execution_grant_secret="short",
        )

    project_secret = "project-" + "p" * 32

    with pytest.raises(RuntimeConfigurationError, match="must be different"):
        settings.validate_secrets(
            project_api_key=project_secret,
            admin_api_key="admin-" + "a" * 32,
            execution_grant_secret=project_secret,
        )

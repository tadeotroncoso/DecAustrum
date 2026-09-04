import asyncio
from unittest.mock import Mock

import pytest

import app.main as main_module
from app.runtime_config import RuntimeConfigurationError, RuntimeSettings


def test_lifespan_initializes_application(
    monkeypatch,
):
    events = []

    def fake_get_configured_api_key():
        events.append("api_key")
        return "configured-api-key"

    monkeypatch.setattr(
        main_module,
        "get_configured_api_key",
        fake_get_configured_api_key,
    )

    def fake_load_policies(directory):
        events.append(("policies", directory))
        return []

    monkeypatch.setattr(
        main_module,
        "load_policies",
        fake_load_policies,
    )

    monkeypatch.setattr(
        main_module.evidence_store,
        "initialize",
        lambda: events.append("database"),
    )

    def fake_bootstrap_default_project(
        store,
        api_key,
    ):
        events.append(
            (
                "bootstrap",
                store,
                api_key,
            )
        )

    monkeypatch.setattr(
        main_module,
        "bootstrap_default_project",
        fake_bootstrap_default_project,
    )

    def fake_seed_project_policies(
        project_id,
        policies,
        seeded_at,
        audit_context,
    ):
        events.append(
            (
                "seed",
                project_id,
                policies,
                audit_context,
            )
        )

    monkeypatch.setattr(
        main_module.evidence_store,
        "seed_project_policies",
        fake_seed_project_policies,
    )

    async def run_lifespan():
        async with main_module.lifespan(
            main_module.app
        ):
            events.append("running")

    asyncio.run(run_lifespan())

    assert events == [
        "api_key",
        (
            "policies",
            main_module.POLICIES_DIRECTORY,
        ),
        "database",
        (
            "bootstrap",
            main_module.evidence_store,
            "configured-api-key",
        ),
        (
            "seed",
            main_module.DEFAULT_PROJECT_ID,
            [],
            main_module.SYSTEM_BOOTSTRAP_AUDIT_CONTEXT,
        ),
        "running",
    ]


@pytest.mark.parametrize(
    "reused_environment_variable",
    [
        "DECAUSTRUM_ADMIN_API_KEY",
        "DECAUSTRUM_EXECUTION_GRANT_SECRET",
    ],
)
def test_production_startup_rejects_reused_webhook_secret_before_storage(
    monkeypatch,
    reused_environment_variable,
):
    monkeypatch.delenv("DECAUSTRUM_API_KEY", raising=False)
    configured_values = {
        "DECAUSTRUM_ADMIN_API_KEY": "a" * 32,
        "DECAUSTRUM_EXECUTION_GRANT_SECRET": "g" * 32,
    }
    for name, value in configured_values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv(
        "DECAUSTRUM_WEBHOOK_MASTER_SECRET",
        configured_values[reused_environment_variable],
    )
    initialize = Mock()
    monkeypatch.setattr(main_module.evidence_store, "initialize", initialize)
    application = main_module.create_app(
        RuntimeSettings.from_environment(
            {
                "DECAUSTRUM_ENVIRONMENT": "production",
                "DECAUSTRUM_TRUSTED_HOSTS": "api.example.com",
            }
        )
    )

    async def run_lifespan():
        async with main_module.lifespan(application):
            pytest.fail("Production startup must reject reused secrets")

    with pytest.raises(RuntimeConfigurationError, match="must be different"):
        asyncio.run(run_lifespan())

    initialize.assert_not_called()

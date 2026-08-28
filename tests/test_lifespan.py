import asyncio

import app.main as main_module


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
    ):
        events.append(
            (
                "seed",
                project_id,
                policies,
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
        ),
        "running",
    ]

import asyncio

import app.main as main_module


def test_lifespan_validates_configuration_and_policies(
    monkeypatch,
):
    events = []

    monkeypatch.setattr(
        main_module,
        "get_configured_api_key",
        lambda: events.append("api_key"),
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
        "running",
    ]
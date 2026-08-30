import re
import tomllib
from pathlib import Path

import yaml
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from app.observability import REGTRACE_VERSION


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = REPOSITORY_ROOT / "requirements"


def parse_pinned_requirements(path: Path) -> dict[str, str]:
    pinned = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or line.startswith("-r "):
            continue

        requirement = Requirement(line)
        specifiers = list(requirement.specifier)

        assert len(specifiers) == 1
        assert specifiers[0].operator == "=="

        name = canonicalize_name(requirement.name)
        assert name not in pinned
        pinned[name] = specifiers[0].version

    return pinned


def project_dependencies() -> dict[str, str]:
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)

    dependencies = {}

    for raw_requirement in pyproject["project"]["dependencies"]:
        requirement = Requirement(raw_requirement)
        specifiers = list(requirement.specifier)
        assert len(specifiers) == 1
        assert specifiers[0].operator == "=="
        dependencies[canonicalize_name(requirement.name)] = (
            specifiers[0].version
        )

    return dependencies


def test_python_and_backend_versions_are_single_line_pins():
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)

    assert (REPOSITORY_ROOT / ".python-version").read_text(
        encoding="utf-8"
    ).strip() == "3.12.14"
    assert pyproject["project"]["version"] == REGTRACE_VERSION
    assert pyproject["project"]["requires-python"] == ">=3.12,<3.13"
    assert pyproject["build-system"]["requires"] == [
        "setuptools==84.0.0"
    ]


def test_runtime_inputs_metadata_and_lock_are_synchronized():
    direct = project_dependencies()
    runtime_input = parse_pinned_requirements(
        REQUIREMENTS / "runtime.in"
    )
    runtime_lock = parse_pinned_requirements(
        REQUIREMENTS / "runtime.lock"
    )

    assert runtime_input == direct
    assert direct.items() <= runtime_lock.items()


def test_development_input_is_covered_by_lock():
    development_input = parse_pinned_requirements(
        REQUIREMENTS / "dev.in"
    )
    development_lock = parse_pinned_requirements(
        REQUIREMENTS / "dev.lock"
    )

    assert development_input.items() <= development_lock.items()
    assert "-r runtime.in" in (
        REQUIREMENTS / "dev.in"
    ).read_text(encoding="utf-8")
    assert "-r runtime.lock" in (
        REQUIREMENTS / "dev.lock"
    ).read_text(encoding="utf-8")


def test_pip_version_is_consistent_across_automation():
    expected = "26.2.1"
    paths = [
        REPOSITORY_ROOT / "Dockerfile",
        REPOSITORY_ROOT / "scripts" / "bootstrap.ps1",
        REPOSITORY_ROOT / "scripts" / "bootstrap.sh",
        REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml",
    ]

    for path in paths:
        assert f"pip=={expected}" in path.read_text(encoding="utf-8") or (
            path.name == "Dockerfile"
            and f"PIP_VERSION={expected}" in path.read_text(
                encoding="utf-8"
            )
        )


def test_automated_lock_installation_never_resolves_unpinned_packages():
    paths = [
        REPOSITORY_ROOT / "Dockerfile",
        REPOSITORY_ROOT / "scripts" / "bootstrap.ps1",
        REPOSITORY_ROOT / "scripts" / "bootstrap.sh",
        REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml",
    ]

    for path in paths:
        content = path.read_text(encoding="utf-8")
        assert "--no-deps" in content


def test_container_is_pinned_and_runs_without_root():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
    first_from = next(
        line for line in dockerfile.splitlines() if line.startswith("FROM ")
    )

    assert re.fullmatch(
        r"FROM python:3\.12\.14-slim-bookworm@sha256:[0-9a-f]{64}",
        first_from,
    )
    assert "COPY requirements/runtime.lock" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert '"--no-access-log"' in dockerfile


def test_compose_defines_hardened_api_worker_and_persistent_data():
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "compose.yaml").read_text(encoding="utf-8")
    )
    services = compose["services"]

    assert set(services) == {"api", "webhook-worker"}

    for service in services.values():
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert "regtrace-data:/app/data" in service["volumes"]
        assert service["env_file"] == [".env"]

    assert services["webhook-worker"]["healthcheck"] == {
        "disable": True
    }
    assert services["webhook-worker"]["depends_on"]["api"] == {
        "condition": "service_healthy"
    }
    assert compose["volumes"]["regtrace-data"]["name"] == (
        "regtrace-data"
    )


def test_ci_actions_are_immutable_and_cover_tests_packages_and_image():
    workflow_path = (
        REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
    )
    workflow_text = workflow_path.read_text(encoding="utf-8")
    workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)
    uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow_text, re.M)

    assert workflow["name"] == "CI"
    assert uses
    assert all(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}", use)
        for use in uses
    )
    assert "python -m pytest -q -p no:cacheprovider" in workflow_text
    assert "python -m pip wheel ./sdk/python" in workflow_text
    assert "docker compose config --quiet" in workflow_text
    assert "docker build --tag regtrace-backend:ci ." in workflow_text
    assert "/health/ready" in workflow_text


def test_docker_context_excludes_secrets_state_and_development_files():
    ignored = set(
        (REPOSITORY_ROOT / ".dockerignore")
        .read_text(encoding="utf-8")
        .splitlines()
    )

    assert {".env", ".git", ".venv", "data", "tests", "sdk"} <= ignored


def test_local_scripts_use_the_same_locks_and_environment_file():
    scripts = REPOSITORY_ROOT / "scripts"
    bootstrap_files = [
        scripts / "bootstrap.ps1",
        scripts / "bootstrap.sh",
    ]
    run_files = [
        scripts / "run-api.ps1",
        scripts / "run-api.sh",
        scripts / "run-worker.ps1",
        scripts / "run-worker.sh",
    ]

    for path in bootstrap_files:
        content = path.read_text(encoding="utf-8")
        assert "requirements" in content
        assert "dev.lock" in content
        assert "runtime.lock" in content

    for path in run_files:
        assert ".env" in path.read_text(encoding="utf-8")

    for path in scripts.glob("*.ps1"):
        assert "$LASTEXITCODE" in path.read_text(encoding="utf-8")

    for path in [scripts / "check.ps1", scripts / "check.sh"]:
        content = path.read_text(encoding="utf-8")
        assert "sdk-python" in content
        assert "sdk/python/src" in content.replace("\\", "/")

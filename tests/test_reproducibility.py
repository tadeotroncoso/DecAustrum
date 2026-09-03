import ast
import json
import re
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from app.observability import DECAUSTRUM_VERSION

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = REPOSITORY_ROOT / "requirements"


def parse_pinned_requirements(path: Path) -> dict[str, str]:
    pinned = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if (
            not line
            or line.startswith(("#", "-r ", "--hash="))
        ):
            continue

        line = line.removesuffix("\\").strip()
        requirement = Requirement(line)
        specifiers = list(requirement.specifier)

        assert len(specifiers) == 1
        assert specifiers[0].operator == "=="

        name = canonicalize_name(requirement.name)
        assert name not in pinned
        pinned[name] = specifiers[0].version

    return pinned


def requirement_hashes(path: Path) -> dict[str, list[str]]:
    hashes: dict[str, list[str]] = {}
    current_name = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith(("#", "-r ")):
            continue

        if line.startswith("--hash=sha256:"):
            assert current_name is not None
            digest = (
                line.removesuffix("\\").split(":", 1)[1].strip()
            )
            assert re.fullmatch(r"[0-9a-f]{64}", digest)
            hashes[current_name].append(digest)
            continue

        requirement = Requirement(line.removesuffix("\\").strip())
        current_name = canonicalize_name(requirement.name)
        assert current_name not in hashes
        hashes[current_name] = []

    return hashes


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
    assert pyproject["project"]["version"] == DECAUSTRUM_VERSION
    assert pyproject["project"]["requires-python"] == ">=3.12,<3.13"
    assert pyproject["build-system"]["requires"] == [
        "setuptools==84.0.0"
    ]


@pytest.mark.parametrize("name", ["bootstrap", "runtime", "dev"])
def test_pip_compile_locks_use_dependabot_compatible_names(name):
    manifest = REQUIREMENTS / f"{name}.in"
    lock = manifest.with_suffix(".txt")

    assert manifest.is_file()
    assert lock.is_file()
    assert lock.stat().st_size <= 500_000
    assert not manifest.with_suffix(".lock").exists()


@pytest.mark.parametrize(
    ("entrypoint", "name"),
    [("requirements.txt", "runtime"), ("requirements-dev.txt", "dev")],
)
def test_requirement_entrypoints_reference_existing_text_locks(entrypoint, name):
    content = (REPOSITORY_ROOT / entrypoint).read_text(encoding="utf-8")

    assert content.strip() == f"-r requirements/{name}.txt"
    assert (REQUIREMENTS / f"{name}.txt").is_file()


def test_runtime_inputs_metadata_and_lock_are_synchronized():
    direct = project_dependencies()
    runtime_input = parse_pinned_requirements(
        REQUIREMENTS / "runtime.in"
    )
    runtime_lock = parse_pinned_requirements(
        REQUIREMENTS / "runtime.txt"
    )

    assert runtime_input == direct
    assert direct.items() <= runtime_lock.items()


def test_runtime_lock_does_not_require_package_installers():
    runtime_lock = parse_pinned_requirements(
        REQUIREMENTS / "runtime.txt"
    )

    assert {"pip", "setuptools", "wheel"}.isdisjoint(runtime_lock)


def test_development_input_is_covered_by_lock():
    development_input = parse_pinned_requirements(
        REQUIREMENTS / "dev.in"
    )
    development_lock = parse_pinned_requirements(
        REQUIREMENTS / "dev.txt"
    )

    assert development_input.items() <= development_lock.items()
    assert "-r runtime.in" in (
        REQUIREMENTS / "dev.in"
    ).read_text(encoding="utf-8")
    runtime_lock = parse_pinned_requirements(
        REQUIREMENTS / "runtime.txt"
    )
    assert runtime_lock.items() <= development_lock.items()
    assert {
        "bandit",
        "coverage",
        "detect-secrets",
        "mypy",
        "pip-audit",
        "pip-tools",
        "pytest-cov",
        "ruff",
        "types-pyyaml",
    } <= development_input.keys()


def test_lock_files_contain_reviewable_sha256_hashes():
    for lock_name in (
        "bootstrap.txt",
        "runtime.txt",
        "dev.txt",
    ):
        lock_path = REQUIREMENTS / lock_name
        locked = parse_pinned_requirements(lock_path)
        hashes = requirement_hashes(lock_path)

        assert hashes.keys() == locked.keys()
        assert all(package_hashes for package_hashes in hashes.values())


def test_pip_bootstrap_is_pinned_and_hash_verified_everywhere():
    assert parse_pinned_requirements(
        REQUIREMENTS / "bootstrap.in"
    ) == {"pip": "26.2.1"}
    assert parse_pinned_requirements(
        REQUIREMENTS / "bootstrap.txt"
    ) == {"pip": "26.2.1"}

    paths = [
        REPOSITORY_ROOT / "Dockerfile",
        REPOSITORY_ROOT / "scripts" / "bootstrap.ps1",
        REPOSITORY_ROOT / "scripts" / "bootstrap.sh",
        REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml",
    ]

    for path in paths:
        content = path.read_text(encoding="utf-8")
        assert "requirements/bootstrap.txt" in content.replace(
            "\\", "/"
        )
        assert "pip install --upgrade pip==" not in content


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
        assert "--require-hashes" in content


def test_container_is_pinned_and_runs_without_root():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
    first_from = next(
        line for line in dockerfile.splitlines() if line.startswith("FROM ")
    )

    assert re.fullmatch(
        r"FROM python:3\.12\.14-alpine3\.23@sha256:[0-9a-f]{64}",
        first_from,
    )
    assert "# syntax=docker/dockerfile" not in dockerfile
    assert (
        "COPY requirements/bootstrap.txt requirements/runtime.txt"
        in dockerfile
    )
    assert "USER 10001:10001" in dockerfile
    assert "addgroup -S -g 10001" in dockerfile
    assert "adduser -S -D -H -u 10001" in dockerfile
    assert "-s /sbin/nologin" in dockerfile
    assert "chmod 0700 /app/data" in dockerfile
    assert dockerfile.count("--only-binary=:all:") == 2
    assert "HEALTHCHECK" in dockerfile
    assert '"--no-access-log"' in dockerfile


def test_container_validates_dependencies_before_removing_installers():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
    instructions = dockerfile.replace("\\\n", " ").splitlines()
    installation = next(
        line for line in instructions
        if line.startswith("RUN python -m pip install ")
    )
    commands = [
        command.strip()
        for command in installation.removeprefix("RUN ").split("&&")
    ]

    assert len(commands) == 5
    assert "requirements/bootstrap.txt" in commands[0]
    assert "requirements/runtime.txt" in commands[1]
    assert commands[2:] == [
        "python -m pip check",
        "python -m pip uninstall --yes pip",
        "rm -r /usr/local/lib/python3.12/ensurepip",
    ]


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
        assert "decaustrum-data:/app/data" in service["volumes"]
        assert service["env_file"] == [".env"]

    assert services["webhook-worker"]["healthcheck"] == {
        "disable": True
    }
    assert services["webhook-worker"]["depends_on"]["api"] == {
        "condition": "service_healthy"
    }
    assert services["api"]["ports"] == [
        "127.0.0.1:${DECAUSTRUM_PORT:-8000}:8000"
    ]
    assert compose["volumes"]["decaustrum-data"]["name"] == (
        "decaustrum-data"
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
        re.fullmatch(
            r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
            r"(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}",
            use,
        )
        for use in uses
    )
    checkout_count = workflow_text.count("uses: actions/checkout@")
    assert workflow_text.count("persist-credentials: false") == (
        checkout_count
    )
    assert workflow_text.count("permissions:") >= 5
    assert "permissions: {}" in workflow_text
    assert "python -m pytest -q -p no:cacheprovider" in workflow_text
    assert "--cov=app" in workflow_text
    assert "--cov=decaustrum" in workflow_text
    assert "--cov-branch" in workflow_text
    assert "python -m ruff check" in workflow_text
    assert "python -m mypy" in workflow_text
    assert "for script in scripts/*.sh; do" in workflow_text
    assert 'sh -n "$script"' in workflow_text
    assert "python -m pip_audit" in workflow_text
    assert "requirements/bootstrap.txt" in workflow_text
    assert "python -m bandit" in workflow_text
    assert "detect-secrets-hook" in workflow_text
    assert "validate_secrets_baseline.py" in workflow_text
    assert "github/codeql-action/init@" in workflow_text
    assert "github/codeql-action/analyze@" in workflow_text
    assert "actions/dependency-review-action@" in workflow_text
    assert workflow_text.count("aquasecurity/trivy-action@") == 2
    assert "version: v0.74.0" in workflow_text
    assert "python -m pip wheel ./sdk/python" in workflow_text
    assert "docker compose config --quiet" in workflow_text
    assert "docker build --tag decaustrum-backend:ci ." in workflow_text
    assert "/health/ready" in workflow_text


def test_image_security_gate_rejects_unfixed_high_and_critical_findings():
    workflow = yaml.load(
        (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        ),
        Loader=yaml.BaseLoader,
    )
    job = workflow["jobs"]["container-smoke-test"]
    image_scans = [
        step
        for step in job["steps"]
        if step.get("with", {}).get("scan-type") == "image"
    ]
    assert len(image_scans) == 1
    step = image_scans[0]
    options = step["with"]
    assert options["ignore-unfixed"] == "false"
    assert options["scanners"] == "vuln"
    assert options["exit-code"] == "1"
    assert set(options["severity"].split(",")) == {"HIGH", "CRITICAL"}
    assert set(options["vuln-type"].split(",")) == {"os", "library"}
    assert step.get("continue-on-error", "false") == "false"
    assert job.get("continue-on-error", "false") == "false"


def test_container_smoke_covers_native_runtime_storage_and_worker():
    workflow = yaml.load(
        (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        ),
        Loader=yaml.BaseLoader,
    )
    step = next(
        step
        for step in workflow["jobs"]["container-smoke-test"]["steps"]
        if step["name"] == "Verify hardened runtime, authorization, and worker"
    )
    smoke = step["run"]
    for required in (
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        '"$volume_name:/app/data"',
        ".State.Health.Status",
        "os.geteuid() == 10001",
        "import pydantic_core",
        "import yaml",
        "ssl.create_default_context().get_ca_certs()",
        "sqlite3.connect",
        "/v1/authorize",
        "/v1/decisions/",
        "python -m app.webhook_worker --once",
    ):
        assert required in smoke
    assert "exit 0" not in smoke
    assert "python -m pip check" not in smoke
    python_probe = smoke.split("python - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    tree = ast.parse(python_probe)
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "verify_runtime_installers_absent"
        for node in ast.walk(tree)
    )


def build_runtime_installer_check(
    *,
    module=None,
    distribution=None,
    executable=None,
):
    workflow = yaml.load(
        (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        ),
        Loader=yaml.BaseLoader,
    )
    smoke = next(
        step["run"]
        for step in workflow["jobs"]["container-smoke-test"]["steps"]
        if step["name"] == "Verify hardened runtime, authorization, and worker"
    )
    python_probe = smoke.split("python - <<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    function = next(
        node for node in ast.parse(python_probe).body
        if isinstance(node, ast.FunctionDef)
        and node.name == "verify_runtime_installers_absent"
    )
    names = ["fastapi", "pydantic", "uvicorn", "PyYAML"]
    if distribution is not None:
        names.append(distribution)
    namespace = {
        "find_spec": lambda name: object() if name == module else None,
        "distributions": lambda: [
            SimpleNamespace(metadata={"Name": name}) for name in names
        ],
        "which": lambda name: (
            f"/usr/local/bin/{name}" if name == executable else None
        ),
    }
    # Run only the CI installer check, not its container or HTTP probes.
    exec(
        compile(
            ast.Module(body=[function], type_ignores=[]),
            "ci-runtime-installer-check",
            "exec",
        ),
        namespace,
    )
    return namespace["verify_runtime_installers_absent"]


def test_container_installer_check_accepts_an_installer_free_runtime():
    build_runtime_installer_check()()


@pytest.mark.parametrize("module", ["pip", "ensurepip", "setuptools", "wheel"])
def test_container_installer_check_rejects_installer_modules(module):
    check = build_runtime_installer_check(module=module)

    with pytest.raises(AssertionError, match="Unexpected installer module"):
        check()


@pytest.mark.parametrize("distribution", ["Pip", "Setuptools", "Wheel"])
def test_container_installer_check_rejects_leftover_metadata(distribution):
    check = build_runtime_installer_check(distribution=distribution)

    with pytest.raises(AssertionError, match="Unexpected installer distribution"):
        check()


@pytest.mark.parametrize("executable", ["pip", "pip3", "pip3.12"])
def test_container_installer_check_rejects_leftover_commands(executable):
    check = build_runtime_installer_check(executable=executable)

    with pytest.raises(AssertionError, match="Unexpected installer command"):
        check()


def test_docker_context_excludes_secrets_state_and_development_files():
    ignored = set(
        (REPOSITORY_ROOT / ".dockerignore")
        .read_text(encoding="utf-8")
        .splitlines()
    )

    assert {
        ".env", ".git", ".venv", "data", "tests", "sdk",
        "requirements/dev.in", "requirements/dev.txt",
    } <= ignored


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
        assert "bootstrap.txt" in content
        assert "dev.txt" in content
        assert "runtime.txt" in content

    powershell_bootstrap = bootstrap_files[0].read_text(
        encoding="utf-8"
    )
    assert "[string]$Python" in powershell_bootstrap
    assert "DECAUSTRUM_PYTHON" in powershell_bootstrap

    for path in run_files:
        assert ".env" in path.read_text(encoding="utf-8")

    for path in scripts.glob("*.ps1"):
        assert "$LASTEXITCODE" in path.read_text(encoding="utf-8")

    for path in [scripts / "check.ps1", scripts / "check.sh"]:
        content = path.read_text(encoding="utf-8")
        assert "sdk-python" in content
        assert "sdk/python/src" in content.replace("\\", "/")
        assert "security-check" in content
        assert "ruff check" in content
        assert "mypy" in content
        assert "--cov=app" in content
        assert "--cov=decaustrum" in content
        assert "--cov-branch" in content

    for path in [
        scripts / "security-check.ps1",
        scripts / "security-check.sh",
    ]:
        content = path.read_text(encoding="utf-8")
        assert "pip_audit" in content
        assert "requirements/dev.txt" in content.replace("\\", "/")
        assert "--require-hashes" in content
        assert "bandit" in content
        assert "detect-secrets-hook" in content
        assert "validate_secrets_baseline.py" in content


def test_bandit_scans_backend_sdk_and_scripts_in_every_security_gate():
    paths = [
        REPOSITORY_ROOT / "scripts" / "security-check.ps1",
        REPOSITORY_ROOT / "scripts" / "security-check.sh",
        REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml",
    ]

    for path in paths:
        content = path.read_text(encoding="utf-8").replace("\\", "/")
        command = re.search(
            r"-m bandit(?P<arguments>.*?--quiet)",
            content,
            re.DOTALL,
        )

        assert command is not None

        arguments = command.group("arguments")
        assert "--recursive" in arguments

        for target in ("app", "sdk/python/src", "scripts"):
            assert target in arguments


def test_posix_security_gate_fails_closed_during_file_discovery():
    content = (
        REPOSITORY_ROOT / "scripts" / "security-check.sh"
    ).read_text(encoding="utf-8")

    assert "publishable_file_list=$(mktemp" in content
    assert "if ! git ls-files" in content
    assert '> "$publishable_file_list"' in content
    assert '[ ! -s "$publishable_file_list" ]' in content
    assert '< "$publishable_file_list"' in content
    assert (
        "git ls-files --cached --others --exclude-standard -z |"
        not in content
    )


def test_release_contract_documents_historical_secret_strategy():
    operations = (
        REPOSITORY_ROOT / "docs" / "operations.md"
    ).read_text(encoding="utf-8")
    normalized_operations = " ".join(operations.split())

    assert "full reachable Git history" in normalized_operations
    assert "GitHub Secret Scanning" in normalized_operations
    assert "Push Protection" in normalized_operations
    assert "rotate or revoke it immediately" in normalized_operations


def test_secret_baseline_is_explicit_and_reviewable():
    secrets = json.loads(
        (REPOSITORY_ROOT / ".secrets.baseline").read_text(
            encoding="utf-8"
        )
    )
    secret_findings = [
        finding
        for findings in secrets["results"].values()
        for finding in findings
    ]

    assert secret_findings
    assert all(
        finding["type"] in {
            "Basic Auth Credentials",
            "Secret Keyword",
        }
        for finding in secret_findings
    )
    assert all(
        finding.get("is_secret") is False
        for finding in secret_findings
    )
    assert ".bandit-baseline.json" not in secrets["results"]
    assert ".secrets.baseline" not in secrets["results"]
    assert not (REPOSITORY_ROOT / ".bandit-baseline.json").exists()

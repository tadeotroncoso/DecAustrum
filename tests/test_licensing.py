import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
LICENSE_EXPRESSION = (
    "LicenseRef-DecAustrum-Portfolio-Evaluation-1.0"
)
PRIVATE_PACKAGE_CLASSIFIER = "Private :: Do Not Upload"


def load_project(path: Path) -> dict:
    with path.open("rb") as file:
        return tomllib.load(file)["project"]


def locked_requirement_names(path: Path) -> set[str]:
    names = set()

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if (
            not line
            or line.startswith(("#", "-r ", "--hash="))
        ):
            continue

        line = line.removesuffix("\\").strip()
        names.add(canonicalize_name(Requirement(line).name))

    return names


def test_portfolio_license_is_authoritative_and_packaged_with_sdk():
    root_license = (REPOSITORY_ROOT / "LICENSE").read_text(
        encoding="utf-8"
    )
    sdk_license = (
        REPOSITORY_ROOT / "sdk" / "python" / "LICENSE"
    ).read_text(encoding="utf-8")

    assert sdk_license == root_license
    assert (
        "Copyright (c) 2026 Tadeo Adrián Troncoso Taraborrelli"
        in root_license
    )
    assert "source-available portfolio evaluation license" in root_license
    assert "open-source license." in root_license
    assert "No support or maintenance" in root_license
    assert "Disclaimer of warranties" in root_license

    sdk_notices = (
        REPOSITORY_ROOT
        / "sdk"
        / "python"
        / "THIRD_PARTY_NOTICES.md"
    ).read_text(encoding="utf-8")
    assert "does not bundle HTTPX" in " ".join(sdk_notices.split())


def test_distribution_metadata_declares_restricted_license():
    projects = [
        load_project(REPOSITORY_ROOT / "pyproject.toml"),
        load_project(
            REPOSITORY_ROOT / "sdk" / "python" / "pyproject.toml"
        ),
    ]

    for project in projects:
        assert project["authors"] == [
            {
                "name": "Tadeo Adrián Troncoso Taraborrelli",
                "email": (
                    "35420076+tadeotroncoso"
                    "@users.noreply.github.com"
                ),
            }
        ]
        assert project["license"] == LICENSE_EXPRESSION
        assert project["license-files"] == [
            "LICENSE",
            "THIRD_PARTY_NOTICES.md",
        ]
        assert PRIVATE_PACKAGE_CLASSIFIER in project["classifiers"]
        assert not any(
            classifier.startswith("License ::")
            for classifier in project["classifiers"]
        )


def test_third_party_notices_cover_distributed_python_dependencies():
    notice_text = (
        REPOSITORY_ROOT / "THIRD_PARTY_NOTICES.md"
    ).read_text(encoding="utf-8")
    listed_names = {
        canonicalize_name(name)
        for name in re.findall(r"^\| `([^`]+)` \|", notice_text, re.M)
    }
    required_names = locked_requirement_names(
        REPOSITORY_ROOT / "requirements" / "runtime.txt"
    ) | {
        "httpx",
        "httpcore",
        "certifi",
    }

    assert required_names <= listed_names
    for license_name in (
        "MIT",
        "BSD-3-Clause",
        "PSF-2.0",
        "MPL-2.0",
    ):
        assert license_name in notice_text


def test_delivery_paths_preserve_legal_files():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(
        encoding="utf-8"
    )
    powershell_check = (
        REPOSITORY_ROOT / "scripts" / "check.ps1"
    ).read_text(encoding="utf-8")
    shell_check = (
        REPOSITORY_ROOT / "scripts" / "check.sh"
    ).read_text(encoding="utf-8")

    assert "LICENSE THIRD_PARTY_NOTICES.md ./" in dockerfile
    assert '"sdk\\python\\LICENSE"' in powershell_check
    assert '"sdk\\python\\THIRD_PARTY_NOTICES.md"' in (
        powershell_check
    )
    assert '"$repository_root/sdk/python/LICENSE"' in shell_check
    assert (
        '"$repository_root/sdk/python/THIRD_PARTY_NOTICES.md"'
        in shell_check
    )


def test_container_notices_match_the_pinned_base_image():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")
    notices = (REPOSITORY_ROOT / "THIRD_PARTY_NOTICES.md").read_text(
        encoding="utf-8"
    )
    base_reference = next(
        line.removeprefix("FROM ").split("@", 1)[0]
        for line in dockerfile.splitlines()
        if line.startswith("FROM ")
    )

    assert f"`{base_reference}`" in notices
    assert "Alpine Linux" in notices
    assert "musl" in notices
    assert "BusyBox" in notices

import ast
import tomllib
from pathlib import Path

from decaustrum import __version__


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SDK_ROOT = REPOSITORY_ROOT / "sdk" / "python"
SDK_PACKAGE = SDK_ROOT / "src" / "decaustrum"


def test_sdk_package_metadata_matches_runtime_version():
    with (SDK_ROOT / "pyproject.toml").open("rb") as file:
        pyproject = tomllib.load(file)

    project = pyproject["project"]

    assert project["name"] == "decaustrum-sdk"
    assert project["version"] == __version__
    assert project["requires-python"] == ">=3.11"
    assert project["dependencies"] == ["httpx>=0.27,<1"]
    assert (SDK_PACKAGE / "py.typed").is_file()


def test_sdk_source_never_imports_backend_modules():
    forbidden_imports = []

    for path in SDK_PACKAGE.glob("*.py"):
        tree = ast.parse(
            path.read_text(encoding="utf-8"),
            filename=str(path),
        )

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module == "app" or module.startswith("app."):
                    forbidden_imports.append((path.name, module))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "app" or alias.name.startswith(
                        "app."
                    ):
                        forbidden_imports.append(
                            (path.name, alias.name)
                        )

    assert forbidden_imports == []


def test_sdk_example_is_valid_python():
    example = SDK_ROOT / "examples" / "protected_bank_transfer.py"

    compile(
        example.read_text(encoding="utf-8"),
        str(example),
        "exec",
    )

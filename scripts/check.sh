#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
virtual_python="$repository_root/.venv/bin/python"

if [ ! -x "$virtual_python" ]; then
    echo "Run scripts/bootstrap.sh before the project checks." >&2
    exit 1
fi

"$repository_root/scripts/security-check.sh"

artifact_directory=$(mktemp -d "${TMPDIR:-/tmp}/decaustrum-build.XXXXXX")
trap 'rm -rf "$artifact_directory"' EXIT HUP INT TERM
sdk_build_source="$artifact_directory/sdk-python"
wheel_directory="$artifact_directory/wheel"
mkdir "$sdk_build_source" "$wheel_directory"
cp "$repository_root/sdk/python/pyproject.toml" "$sdk_build_source/"
cp "$repository_root/sdk/python/README.md" "$sdk_build_source/"
cp "$repository_root/sdk/python/LICENSE" "$sdk_build_source/"
cp "$repository_root/sdk/python/THIRD_PARTY_NOTICES.md" "$sdk_build_source/"
cp -R "$repository_root/sdk/python/src" "$sdk_build_source/"

"$virtual_python" -m pip check
"$virtual_python" -m ruff check app sdk/python/src scripts tests
"$virtual_python" -m mypy
"$virtual_python" -m pytest \
    -q \
    -p no:cacheprovider \
    --cov=app \
    --cov=decaustrum \
    --cov-branch \
    --cov-report=term-missing
"$virtual_python" -m pip wheel \
    --no-deps \
    --no-build-isolation \
    --wheel-dir "$wheel_directory" \
    "$sdk_build_source"

echo "DecAustrum quality, tests, and package builds passed."

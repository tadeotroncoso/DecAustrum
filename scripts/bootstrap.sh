#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_command=${DECAUSTRUM_PYTHON:-python3}
python_minor=$(
    "$python_command" -c \
        'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
)

if [ "$python_minor" != "3.12" ]; then
    echo "DecAustrum requires Python 3.12; found $python_minor." >&2
    exit 1
fi

virtual_environment="$repository_root/.venv"
virtual_python="$virtual_environment/bin/python"

if [ ! -x "$virtual_python" ]; then
    "$python_command" -m venv "$virtual_environment"
fi

"$virtual_python" -m pip install \
    --upgrade \
    --require-hashes \
    --no-deps \
    --only-binary=:all: \
    --requirement "$repository_root/requirements/bootstrap.lock"

if [ "${1:-}" = "--runtime" ]; then
    lock_file="$repository_root/requirements/runtime.lock"
else
    lock_file="$repository_root/requirements/dev.lock"
fi

"$virtual_python" -m pip install \
    --require-hashes \
    --no-deps \
    --requirement "$lock_file"
"$virtual_python" -m pip check

if [ "${1:-}" != "--runtime" ]; then
    "$virtual_python" -m pip install \
        --no-deps \
        --no-build-isolation \
        --editable "$repository_root"
    "$virtual_python" -m pip install \
        --no-deps \
        --no-build-isolation \
        --editable "$repository_root/sdk/python"
fi

printf 'DecAustrum environment is ready at %s\n' "$virtual_environment"

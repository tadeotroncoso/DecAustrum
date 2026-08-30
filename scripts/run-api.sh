#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
virtual_python="$repository_root/.venv/bin/python"
environment_file="$repository_root/.env"

if [ ! -x "$virtual_python" ]; then
    echo "Run scripts/bootstrap.sh before starting RegTrace." >&2
    exit 1
fi

if [ ! -f "$environment_file" ]; then
    echo "Copy .env.example to .env and configure local secrets first." >&2
    exit 1
fi

exec "$virtual_python" -m uvicorn app.main:app \
    --app-dir "$repository_root" \
    --env-file "$environment_file" \
    --host 127.0.0.1 \
    --port 8000 \
    --no-access-log

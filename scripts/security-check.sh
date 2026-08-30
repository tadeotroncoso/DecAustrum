#!/usr/bin/env sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
virtual_python="$repository_root/.venv/bin/python"
detect_secrets_hook="$repository_root/.venv/bin/detect-secrets-hook"
secrets_baseline="$repository_root/.secrets.baseline"
baseline_validator="$repository_root/scripts/validate_secrets_baseline.py"

if [ ! -x "$virtual_python" ] || \
    [ ! -x "$detect_secrets_hook" ] || \
    [ ! -f "$secrets_baseline" ] || \
    [ ! -f "$baseline_validator" ]; then
    echo "Run scripts/bootstrap.sh before the security gate." >&2
    exit 1
fi

cd "$repository_root"

"$virtual_python" "$baseline_validator" "$secrets_baseline"

"$virtual_python" -m pip_audit \
    --requirement requirements/dev.lock \
    --no-deps \
    --disable-pip \
    --progress-spinner off

if ! bandit_output=$("$virtual_python" -m bandit \
    --recursive app \
    --quiet 2>&1); then
    printf '%s\n' "$bandit_output" >&2
    exit 1
fi

git ls-files --cached --others --exclude-standard -z | \
    xargs -0 "$detect_secrets_hook" \
        --baseline .secrets.baseline \
        --no-verify \
        --exclude-files '^\.(bandit-baseline\.json|secrets\.baseline)$'

echo "RegTrace security gate passed."

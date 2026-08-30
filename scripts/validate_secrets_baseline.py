"""Validate that every detect-secrets baseline finding was reviewed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


class SecretsBaselineValidationError(ValueError):
    """Raised when a secret baseline is malformed or not fully reviewed."""


def _finding_location(filename: str, finding: dict[str, Any]) -> str:
    return f"{filename}:{finding.get('line_number', '?')}"


def validate_secrets_baseline(path: Path) -> int:
    """Return the finding count when every entry is explicitly safe."""
    try:
        baseline = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecretsBaselineValidationError(
            f"Could not read {path}: {exc}"
        ) from exc

    if not isinstance(baseline, dict):
        raise SecretsBaselineValidationError(
            "Secret baseline root must be an object."
        )

    results = baseline.get("results")

    if not isinstance(results, dict):
        raise SecretsBaselineValidationError(
            "Secret baseline results must be an object."
        )

    unreviewed: list[str] = []
    confirmed: list[str] = []
    invalid: list[str] = []
    finding_count = 0

    for filename, findings in results.items():
        if not isinstance(filename, str) or not isinstance(findings, list):
            raise SecretsBaselineValidationError(
                "Secret baseline results have an invalid structure."
            )

        for finding in findings:
            if not isinstance(finding, dict):
                raise SecretsBaselineValidationError(
                    f"Secret baseline findings for {filename} must be objects."
                )

            finding_count += 1
            location = _finding_location(filename, finding)
            review = finding.get("is_secret")

            if review is None:
                unreviewed.append(location)
            elif review is True:
                confirmed.append(location)
            elif review is not False:
                invalid.append(location)

    problems = []

    if unreviewed:
        problems.append("unreviewed findings: " + ", ".join(unreviewed))
    if confirmed:
        problems.append("confirmed secrets: " + ", ".join(confirmed))
    if invalid:
        problems.append("invalid review values: " + ", ".join(invalid))

    if problems:
        raise SecretsBaselineValidationError("; ".join(problems))

    return finding_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject a detect-secrets baseline containing unreviewed or "
            "confirmed-secret findings."
        )
    )
    parser.add_argument("baseline", type=Path)
    arguments = parser.parse_args(argv)

    try:
        finding_count = validate_secrets_baseline(arguments.baseline)
    except SecretsBaselineValidationError as exc:
        print(f"Secret baseline review failed: {exc}", file=sys.stderr)
        return 1

    print(
        "Secret baseline review passed "
        f"({finding_count} reviewed false positives)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

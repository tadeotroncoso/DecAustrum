"""Validate that every detect-secrets baseline finding was reviewed."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn


class SecretsBaselineValidationError(ValueError):
    """A validation failure with only locally generated, log-safe diagnostics."""


class _BaselineArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's default error includes unrecognized user-supplied arguments.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid arguments: provide exactly one baseline file.\n")


def _finding_location(file_index: int, finding_index: int) -> str:
    # Never echo filenames or metadata: even a location can contain credentials.
    return f"file entry {file_index}, finding {finding_index}"


def validate_secrets_baseline(path: Path) -> int:
    """Return the finding count when every entry is explicitly safe."""
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeError:
        raise SecretsBaselineValidationError(
            "Secret baseline must be valid UTF-8 text."
        ) from None
    except (OSError, ValueError):
        raise SecretsBaselineValidationError(
            "Could not read the baseline file."
        ) from None

    try:
        baseline = json.loads(content)
    except (ValueError, RecursionError):
        # JSON errors, including excessive integer/depth limits, must not expose
        # the input or the original exception through CLI output or tracebacks.
        raise SecretsBaselineValidationError(
            "Secret baseline must contain valid JSON within parser limits."
        ) from None

    if not isinstance(baseline, dict):
        raise SecretsBaselineValidationError("Secret baseline root must be an object.")

    results = baseline.get("results")

    if not isinstance(results, dict):
        raise SecretsBaselineValidationError(
            "Secret baseline results must be an object."
        )

    unreviewed: list[str] = []
    confirmed: list[str] = []
    invalid: list[str] = []
    finding_count = 0

    for file_index, (filename, findings) in enumerate(results.items(), start=1):
        if (
            not isinstance(filename, str)
            or not filename
            or not isinstance(findings, list)
        ):
            raise SecretsBaselineValidationError(
                "Secret baseline results have an invalid structure."
            )

        for finding_index, finding in enumerate(findings, start=1):
            location = _finding_location(file_index, finding_index)
            if not isinstance(finding, dict):
                raise SecretsBaselineValidationError(
                    f"Secret baseline finding at {location} must be an object."
                )

            # Slim detect-secrets baselines may omit line_number. If present,
            # accept only positive integers, not booleans, strings or containers.
            if "line_number" in finding:
                line_number = finding["line_number"]
                if type(line_number) is not int or line_number < 1:
                    raise SecretsBaselineValidationError(
                        f"Secret baseline finding at {location} has an invalid "
                        "line_number; expected a positive integer."
                    )

            finding_count += 1
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
    parser = _BaselineArgumentParser(
        prog="validate_secrets_baseline.py",
        description=(
            "Reject a detect-secrets baseline containing unreviewed or "
            "confirmed-secret findings."
        ),
    )
    parser.add_argument("baseline", type=Path)
    arguments = parser.parse_args(argv)

    try:
        validate_secrets_baseline(arguments.baseline)
    except SecretsBaselineValidationError as exc:
        print(f"Secret baseline review failed: {exc}", file=sys.stderr)
        return 1

    print("Secret baseline review passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

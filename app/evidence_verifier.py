import argparse
import json
import re
from collections.abc import Sequence
from pathlib import Path

from app.evidence import (
    EvidenceBundleArchiveError,
    load_evidence_bundle_archive,
    verify_evidence_bundle,
)


SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _sha256_digest(value: str) -> str:
    if SHA256_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "expected a lowercase 64-character SHA-256 digest"
        )

    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.evidence_verifier",
        description=(
            "Verify a DecAustrum evidence bundle without connecting "
            "to its database or API."
        ),
    )
    parser.add_argument(
        "archive",
        type=Path,
        help="Path to a DecAustrum evidence bundle ZIP.",
    )
    parser.add_argument(
        "--expected-head-hash",
        type=_sha256_digest,
        default=None,
        help=(
            "Externally trusted current or historical ledger "
            "checkpoint."
        ),
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)

    try:
        bundle = load_evidence_bundle_archive(arguments.archive)
    except EvidenceBundleArchiveError as exc:
        print(
            json.dumps(
                {
                    "verified": False,
                    "failure": {
                        "code": "archive_invalid",
                        "message": str(exc),
                    },
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    verification = verify_evidence_bundle(
        bundle,
        expected_head_hash=arguments.expected_head_hash,
    )
    print(
        json.dumps(
            verification.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
    )

    return 0 if verification.verified else 1


if __name__ == "__main__":
    raise SystemExit(main())

import json
from pathlib import Path

import pytest

from scripts.validate_secrets_baseline import (
    SecretsBaselineValidationError,
    validate_secrets_baseline,
)


def write_baseline(
    directory: Path,
    finding: dict,
) -> Path:
    path = directory / ".secrets.baseline"
    path.write_text(
        json.dumps(
            {
                "results": {
                    "example.py": [
                        {
                            "type": "Secret Keyword",
                            "line_number": 7,
                            **finding,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_validator_accepts_explicit_false_positive(tmp_path):
    path = write_baseline(tmp_path, {"is_secret": False})

    assert validate_secrets_baseline(path) == 1


@pytest.mark.parametrize(
    ("finding", "message"),
    [
        ({}, "unreviewed findings"),
        ({"is_secret": None}, "unreviewed findings"),
        ({"is_secret": True}, "confirmed secrets"),
        ({"is_secret": 0}, "invalid review values"),
    ],
)
def test_validator_rejects_unsafe_review_state(
    tmp_path,
    finding,
    message,
):
    path = write_baseline(tmp_path, finding)

    with pytest.raises(
        SecretsBaselineValidationError,
        match=message,
    ):
        validate_secrets_baseline(path)

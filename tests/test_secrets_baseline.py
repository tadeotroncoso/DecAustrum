import json
import subprocess
import sys
import traceback
from pathlib import Path

import pytest

from scripts.validate_secrets_baseline import (
    SecretsBaselineValidationError,
    main,
    validate_secrets_baseline,
)

CANARY = "BASELINE_DIAGNOSTIC_MARKER_NOT_A_CREDENTIAL"


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


def write_payload(directory: Path, payload: object) -> Path:
    path = directory / f"{CANARY}.baseline"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def assert_safe_failure(path: Path, capsys, expected: str) -> None:
    assert main([str(path)]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("Secret baseline review failed: ")
    assert expected in output.err
    assert CANARY not in output.err
    assert str(path) not in output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("review", [None, True, 0, 1, "false", [], {}])
def test_cli_uses_only_generated_locations(tmp_path, capsys, review):
    path = write_payload(
        tmp_path,
        {
            "results": {
                f"{CANARY}\nforged log entry": [
                    {
                        "line_number": 987654321,
                        "is_secret": review,
                        "secret_value": CANARY,
                        "hashed_secret": CANARY,
                    }
                ]
            }
        },
    )
    assert main([str(path)]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "file entry 1, finding 1" in output.err
    assert CANARY not in output.err
    assert "forged log entry" not in output.err
    assert "987654321" not in output.err
    assert output.err.count("\n") == 1


@pytest.mark.parametrize(
    "line_number",
    [
        None,
        True,
        False,
        0,
        -1,
        1.5,
        "7",
        CANARY,
        [CANARY],
        {"nested": CANARY},
        f"7\n{CANARY}",
    ],
)
@pytest.mark.parametrize("review", [False, True, None])
def test_cli_rejects_invalid_line_metadata_without_echoing_it(
    tmp_path, capsys, line_number, review
):
    path = write_payload(
        tmp_path,
        {"results": {CANARY: [{"line_number": line_number, "is_secret": review}]}},
    )
    assert_safe_failure(path, capsys, "expected a positive integer")


@pytest.mark.parametrize(
    "finding", [{"is_secret": False}, {"is_secret": False, "line_number": 1}]
)
def test_cli_accepts_valid_and_slim_baselines_without_echoing_contents(
    tmp_path, capsys, finding
):
    path = write_payload(
        tmp_path,
        {
            "results": {
                CANARY: [{**finding, "secret_value": CANARY, "hashed_secret": CANARY}]
            }
        },
    )
    assert main([str(path)]) == 0
    output = capsys.readouterr()
    assert output.out == "Secret baseline review passed.\n"
    assert output.err == ""


def test_cli_reports_all_review_categories_with_stable_positions(tmp_path, capsys):
    path = write_payload(
        tmp_path,
        {
            "results": {
                "first": [{"is_secret": False}, {}],
                CANARY: [{"is_secret": True}, {"is_secret": 0}],
            }
        },
    )
    assert main([str(path)]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        "Secret baseline review failed: "
        "unreviewed findings: file entry 1, finding 2; "
        "confirmed secrets: file entry 2, finding 1; "
        "invalid review values: file entry 2, finding 2\n"
    )


@pytest.mark.parametrize(
    "payload",
    [
        None,
        True,
        123,
        CANARY,
        [],
        {},
        {"results": None},
        {"results": []},
        {"results": CANARY},
        {"results": {CANARY: CANARY}},
        {"results": {CANARY: [None]}},
        {"results": {CANARY: [CANARY]}},
        {"results": {CANARY: [[]]}},
        {"results": {"": []}},
    ],
)
def test_cli_rejects_bad_structures_without_echoing_them(tmp_path, capsys, payload):
    path = write_payload(tmp_path, payload)
    assert_safe_failure(path, capsys, "Secret baseline")


@pytest.mark.parametrize("raw", ["", "{", CANARY, f'{{"value":"{CANARY}",'])
def test_cli_rejects_invalid_json_without_echoing_it(tmp_path, capsys, raw):
    path = tmp_path / f"{CANARY}.baseline"
    path.write_text(raw, encoding="utf-8")
    assert_safe_failure(path, capsys, "valid JSON")


def test_cli_rejects_invalid_utf8_without_traceback(tmp_path, capsys):
    path = tmp_path / f"{CANARY}.baseline"
    path.write_bytes(CANARY.encode("ascii") + b"\xff")
    assert_safe_failure(path, capsys, "valid UTF-8")


def test_cli_hides_missing_input_path(tmp_path, capsys):
    assert_safe_failure(tmp_path / CANARY, capsys, "Could not read")


@pytest.mark.parametrize("error_type", [OSError, PermissionError, ValueError])
def test_read_errors_do_not_expose_original_exception(
    tmp_path, capsys, monkeypatch, error_type
):
    def fail_read(self, **kwargs):
        raise error_type(CANARY)

    monkeypatch.setattr(Path, "read_text", fail_read)
    path = tmp_path / CANARY
    assert_safe_failure(path, capsys, "Could not read")
    with pytest.raises(SecretsBaselineValidationError) as raised:
        validate_secrets_baseline(path)
    # A caller formatting the validation exception must not print its cause.
    assert raised.value.__suppress_context__ is True
    assert CANARY not in "".join(traceback.format_exception(raised.value))


@pytest.mark.parametrize("error_type", [ValueError, RecursionError])
def test_json_parser_limits_fail_with_controlled_messages(
    tmp_path, capsys, monkeypatch, error_type
):
    path = write_payload(tmp_path, {"results": {}})

    def fail_parse(content):
        raise error_type(CANARY)

    monkeypatch.setattr(json, "loads", fail_parse)
    assert_safe_failure(path, capsys, "valid JSON within parser limits")


@pytest.mark.parametrize("arguments", [[], ["--" + CANARY], [CANARY, CANARY]])
def test_cli_argument_errors_do_not_echo_arguments(capsys, monkeypatch, arguments):
    monkeypatch.setattr(sys, "argv", [CANARY])
    with pytest.raises(SystemExit) as raised:
        main(arguments)
    assert raised.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "Invalid arguments: provide exactly one baseline file." in output.err
    assert CANARY not in output.err


@pytest.mark.parametrize("payload", [b"\xff", b"{", None])
def test_real_cli_failure_is_redacted(tmp_path, payload):
    path = tmp_path / f"{CANARY}.baseline"
    if payload is not None:
        path.write_bytes(payload)
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(
                Path(__file__).resolve().parents[1]
                / "scripts"
                / "validate_secrets_baseline.py"
            ),
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "Secret baseline review failed:" in completed.stderr
    assert CANARY not in completed.stderr
    assert "Traceback" not in completed.stderr

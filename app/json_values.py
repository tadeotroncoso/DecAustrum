import json
from typing import Any


def validate_json_value(value: Any, *, name: str) -> Any:
    """Reject values that cannot be represented by strict JSON."""
    try:
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"{name} must contain only finite JSON values."
        ) from exc

    _require_string_object_keys(value, name=name)
    return value


def _require_string_object_keys(value: Any, *, name: str) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if not isinstance(key, str):
                raise ValueError(
                    f"{name} object keys must be strings."
                )

            _require_string_object_keys(nested_value, name=name)
        return

    if isinstance(value, (list, tuple)):
        for nested_value in value:
            _require_string_object_keys(nested_value, name=name)


__all__ = ["validate_json_value"]

from typing import Any


def _values_have_compatible_types(
    actual_value: Any,
    expected_value: Any,
) -> bool:
    if isinstance(actual_value, bool) or isinstance(expected_value, bool):
        return (
            isinstance(actual_value, bool)
            and isinstance(expected_value, bool)
        )

    numeric_types = (int, float)

    if (
        isinstance(actual_value, numeric_types)
        and isinstance(expected_value, numeric_types)
    ):
        return True

    return type(actual_value) is type(expected_value)


def evaluate_operator(
    operator: str,
    actual_value: Any,
    expected_value: Any,
) -> bool:

    if not _values_have_compatible_types(
        actual_value,
        expected_value,
    ):
        raise TypeError(
            f"Incompatible operand types: "
            f"{type(actual_value).__name__} and "
            f"{type(expected_value).__name__}."
        )

    if operator == "greater_than":
        return actual_value > expected_value

    if operator == "less_than":
        return actual_value < expected_value

    if operator == "equals":
        return actual_value == expected_value

    if operator == "not_equals":
        return actual_value != expected_value

    return False
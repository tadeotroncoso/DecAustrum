from typing import Any


def evaluate_operator(
    operator: str,
    actual_value: Any,
    expected_value: Any,
) -> bool:
    if operator == "greater_than":
        return actual_value > expected_value

    if operator == "less_than":
        return actual_value < expected_value

    if operator == "equals":
        return actual_value == expected_value

    if operator == "not_equals":
        return actual_value != expected_value

    return False
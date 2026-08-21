from app.operators import evaluate_operator
import pytest


def test_greater_than():
    assert evaluate_operator("greater_than", 10, 5) is True
    assert evaluate_operator("greater_than", 5, 10) is False


def test_less_than():
    assert evaluate_operator("less_than", 5, 10) is True
    assert evaluate_operator("less_than", 10, 5) is False


def test_equals():
    assert evaluate_operator("equals", "EU", "EU") is True
    assert evaluate_operator("equals", "US", "EU") is False


def test_not_equals():
    assert evaluate_operator("not_equals", "US", "EU") is True
    assert evaluate_operator("not_equals", "EU", "EU") is False

def test_incompatible_types_raise_error():
    with pytest.raises(TypeError):
        evaluate_operator(
            "equals",
            "false",
            False,
        )


def test_numeric_types_are_compatible():
    assert evaluate_operator(
        "greater_than",
        10.5,
        10,
    ) is True
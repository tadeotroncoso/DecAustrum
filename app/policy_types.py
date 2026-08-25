from typing import Literal


Decision = Literal[
    "ALLOW",
    "REQUIRE_APPROVAL",
    "DENY",
]

Operator = Literal[
    "greater_than",
    "less_than",
    "equals",
    "not_equals",
]

ConditionMatch = Literal[
    "all",
    "any",
]
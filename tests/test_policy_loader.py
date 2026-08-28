import pytest

from app.exceptions import DuplicatePolicyIdError
from app.policy_loader import load_policies


def test_load_policies_rejects_duplicate_policy_ids(
    tmp_path,
):
    first_policy = tmp_path / "first.yaml"
    second_policy = tmp_path / "second.yaml"

    first_policy.write_text(
        """
id: duplicate-policy
version: 1
action: send_email
match: all
conditions:
  - field: recipient_verified
    operator: equals
    value: true
decision: ALLOW
reason: First definition.
""".strip(),
        encoding="utf-8",
    )

    second_policy.write_text(
        """
id: duplicate-policy
version: 2
action: send_email
match: all
conditions:
  - field: recipient_verified
    operator: equals
    value: true
decision: DENY
reason: Second definition.
""".strip(),
        encoding="utf-8",
    )

    with pytest.raises(
        DuplicatePolicyIdError,
        match=(
            "Policy id 'duplicate-policy' "
            "is defined more than once."
        ),
    ):
        load_policies(tmp_path)
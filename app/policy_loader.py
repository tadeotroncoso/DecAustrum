from pathlib import Path

import yaml

from app.policy_models import Policy


def load_policy(path: Path) -> Policy:
    with path.open("r", encoding="utf-8") as file:
        raw_policy = yaml.safe_load(file)

    return Policy.model_validate(raw_policy)


def load_policies(directory: Path) -> list[Policy]:
    policies = []

    for path in sorted(directory.glob("*.yaml")):
        policy = load_policy(path)
        policies.append(policy)

    return policies
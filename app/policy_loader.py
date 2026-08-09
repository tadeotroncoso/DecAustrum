from pathlib import Path

import yaml


def load_policy(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def load_policies(directory: Path) -> list[dict]:
    policies = []

    for path in directory.glob("*.yaml"):
        policy = load_policy(path)
        policies.append(policy)

    return policies
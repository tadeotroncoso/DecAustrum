from pathlib import Path
import yaml

def load_policy(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)
import sqlite3
from pathlib import Path


CREATE_DECISIONS_TABLE = """
CREATE TABLE IF NOT EXISTS authorization_decisions (
    decision_id TEXT PRIMARY KEY,
    evaluated_at TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_id TEXT,
    policy_version INTEGER,
    reason TEXT NOT NULL,
    evidence_json TEXT,
    agent TEXT NOT NULL,
    action TEXT NOT NULL,
    context_json TEXT NOT NULL
)
"""


class EvidenceStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with sqlite3.connect(self.database_path) as connection:
            connection.execute(CREATE_DECISIONS_TABLE)
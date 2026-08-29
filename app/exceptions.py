from uuid import UUID


class ApprovalNotFoundError(Exception):
    def __init__(self, decision_id: UUID) -> None:
        self.decision_id = decision_id

        super().__init__(
            f"Approval for decision '{decision_id}' was not found."
        )


class ApprovalAlreadyResolvedError(Exception):
    def __init__(
        self,
        decision_id: UUID,
        current_status: str,
    ) -> None:
        self.decision_id = decision_id
        self.current_status = current_status

        super().__init__(
            f"Approval for decision '{decision_id}' "
            f"is already {current_status}."
        )


class InvalidPolicyContextError(Exception):
    def __init__(
        self,
        field: str,
        operator: str,
    ) -> None:
        self.field = field
        self.operator = operator

        super().__init__(
            f"Context field '{field}' is incompatible "
            f"with operator '{operator}'."
        )

class DuplicatePolicyIdError(Exception):
    def __init__(self, policy_id: str) -> None:
        self.policy_id = policy_id

        super().__init__(
            f"Policy id '{policy_id}' is defined more than once."
        )


class PolicyVersionConflictError(Exception):
    def __init__(
        self,
        policy_id: str,
        expected_version: int,
        provided_version: int,
    ) -> None:
        self.policy_id = policy_id
        self.expected_version = expected_version
        self.provided_version = provided_version

        super().__init__(
            f"Policy '{policy_id}' must use version "
            f"{expected_version}, not {provided_version}."
        )


class PolicyVersionNotFoundError(Exception):
    def __init__(
        self,
        policy_id: str,
        version: int,
    ) -> None:
        self.policy_id = policy_id
        self.version = version

        super().__init__(
            f"Policy '{policy_id}' version {version} "
            "was not found."
        )


class PolicyVersionAlreadyCurrentError(Exception):
    def __init__(
        self,
        policy_id: str,
        version: int,
    ) -> None:
        self.policy_id = policy_id
        self.version = version

        super().__init__(
            f"Policy '{policy_id}' is already at "
            f"version {version}."
        )


class DecisionIntegrityMigrationError(Exception):
    def __init__(
        self,
        project_id: UUID,
        decision_count: int,
        integrity_count: int,
    ) -> None:
        self.project_id = project_id
        self.decision_count = decision_count
        self.integrity_count = integrity_count

        super().__init__(
            f"Project '{project_id}' has {decision_count} "
            "decisions but "
            f"{integrity_count} integrity records."
        )

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
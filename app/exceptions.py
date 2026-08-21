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
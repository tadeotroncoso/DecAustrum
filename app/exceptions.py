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


class ApprovalExpiredError(Exception):
    def __init__(self, decision_id: UUID) -> None:
        self.decision_id = decision_id

        super().__init__(
            f"Approval for decision '{decision_id}' has expired."
        )


class InvalidExecutionGrantError(Exception):
    def __init__(self) -> None:
        super().__init__("Execution grant is invalid.")


class ExecutionGrantAlreadyConsumedError(Exception):
    def __init__(self, grant_id: UUID) -> None:
        self.grant_id = grant_id

        super().__init__(
            f"Execution grant '{grant_id}' has already been consumed."
        )


class ExecutionGrantExpiredError(Exception):
    def __init__(self, grant_id: UUID) -> None:
        self.grant_id = grant_id

        super().__init__(
            f"Execution grant '{grant_id}' has expired."
        )


class ExecutionGrantMismatchError(Exception):
    def __init__(self, grant_id: UUID) -> None:
        self.grant_id = grant_id

        super().__init__(
            f"Execution grant '{grant_id}' does not match the request."
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


class EvidenceExportSizeLimitError(Exception):
    def __init__(self, scope: str, maximum_bytes: int) -> None:
        self.scope = scope
        self.maximum_bytes = maximum_bytes

        super().__init__(
            f"Evidence {scope} exceeds the {maximum_bytes}-byte limit."
        )


class WebhookSubscriptionNotFoundError(Exception):
    def __init__(
        self,
        project_id: UUID,
        subscription_id: UUID,
    ) -> None:
        self.project_id = project_id
        self.subscription_id = subscription_id

        super().__init__(
            f"Webhook subscription '{subscription_id}' was not "
            f"found for project '{project_id}'."
        )


class WebhookSubscriptionDisabledError(Exception):
    def __init__(self, subscription_id: UUID) -> None:
        self.subscription_id = subscription_id

        super().__init__(
            f"Webhook subscription '{subscription_id}' is disabled."
        )


class WebhookEventNotFoundError(Exception):
    def __init__(
        self,
        project_id: UUID,
        event_id: UUID,
    ) -> None:
        self.project_id = project_id
        self.event_id = event_id

        super().__init__(
            f"Webhook event '{event_id}' was not found for "
            f"project '{project_id}'."
        )


class WebhookDeliveryNotFoundError(Exception):
    def __init__(
        self,
        project_id: UUID,
        delivery_id: UUID,
    ) -> None:
        self.project_id = project_id
        self.delivery_id = delivery_id

        super().__init__(
            f"Webhook delivery '{delivery_id}' was not found for "
            f"project '{project_id}'."
        )


class WebhookDeliveryNotRedeliverableError(Exception):
    def __init__(
        self,
        delivery_id: UUID,
        current_status: str,
    ) -> None:
        self.delivery_id = delivery_id
        self.current_status = current_status

        super().__init__(
            f"Webhook delivery '{delivery_id}' cannot be "
            f"redelivered while it is {current_status}."
        )


class WebhookDeliveryStateError(Exception):
    def __init__(
        self,
        delivery_id: UUID,
        current_status: str,
    ) -> None:
        self.delivery_id = delivery_id
        self.current_status = current_status

        super().__init__(
            f"Webhook delivery '{delivery_id}' is {current_status}; "
            "a processing lease is required to complete it."
        )

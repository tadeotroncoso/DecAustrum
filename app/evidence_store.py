from datetime import datetime
from pathlib import Path
from uuid import UUID

from app.api_keys import (
    ProjectApiKeyMetadata,
    ProjectApiKeyRecord,
)
from app.approval_models import (
    ApprovalRecord,
    ApprovalResolutionStatus,
    ApprovalStatus,
)
from app.authorization_models import AuthorizationResponse
from app.idempotency import IdempotencyRecord
from app.policy_models import (
    Policy,
    ProjectPolicyConfiguration,
)
from app.project_models import Project, ProjectStatus
from app.storage.api_keys import ProjectApiKeyRepository
from app.storage.approvals import ApprovalRepository
from app.storage.database import SQLiteDatabase
from app.storage.decisions import (
    AuthorizationDecisionRepository,
)
from app.storage.idempotency import IdempotencyRepository
from app.storage.policies import ProjectPolicyRepository
from app.storage.projects import ProjectRepository


class EvidenceStore:
    """Compatibility facade over domain-specific repositories."""

    def __init__(self, database_path: Path) -> None:
        self.database = SQLiteDatabase(database_path)
        self.projects = ProjectRepository(self.database)
        self.api_keys = ProjectApiKeyRepository(self.database)
        self.policies = ProjectPolicyRepository(self.database)
        self.decisions = AuthorizationDecisionRepository(
            self.database
        )
        self.approvals = ApprovalRepository(self.database)
        self.idempotency = IdempotencyRepository(self.database)

    @property
    def database_path(self) -> Path:
        return self.database.database_path

    def initialize(self) -> None:
        self.database.initialize()

    def save_project(self, project: Project) -> None:
        self.projects.save(project)

    def get_project(
        self,
        project_id: UUID,
    ) -> Project | None:
        return self.projects.get(project_id)

    def list_projects(
        self,
        status: ProjectStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[Project]:
        return self.projects.list(
            status=status,
            limit=limit,
            offset=offset,
        )

    def count_projects(
        self,
        status: ProjectStatus | None = None,
    ) -> int:
        return self.projects.count(status=status)

    def update_project_status(
        self,
        project_id: UUID,
        status: ProjectStatus,
        updated_at: datetime,
    ) -> Project | None:
        return self.projects.update_status(
            project_id=project_id,
            status=status,
            updated_at=updated_at,
        )

    def save(
        self,
        authorization: AuthorizationResponse,
    ) -> None:
        self.decisions.save(authorization)

    def get(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> AuthorizationResponse | None:
        return self.decisions.get(
            decision_id=decision_id,
            project_id=project_id,
        )

    def list_decisions(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[AuthorizationResponse]:
        return self.decisions.list(
            project_id=project_id,
            limit=limit,
            offset=offset,
        )

    def count(self, project_id: UUID) -> int:
        return self.decisions.count(project_id)

    def get_idempotency_record(
        self,
        project_id: UUID,
        idempotency_key: str,
    ) -> IdempotencyRecord | None:
        return self.idempotency.get(
            project_id=project_id,
            idempotency_key=idempotency_key,
        )

    def save_approval(
        self,
        approval: ApprovalRecord,
    ) -> None:
        self.approvals.save(approval)

    def get_approval(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> ApprovalRecord | None:
        return self.approvals.get(
            decision_id=decision_id,
            project_id=project_id,
        )

    def resolve_approval(
        self,
        decision_id: UUID,
        project_id: UUID,
        status: ApprovalResolutionStatus,
        resolved_by: str,
        resolved_at: datetime,
    ) -> ApprovalRecord:
        return self.approvals.resolve(
            decision_id=decision_id,
            project_id=project_id,
            status=status,
            resolved_by=resolved_by,
            resolved_at=resolved_at,
        )

    def list_approvals(
        self,
        project_id: UUID,
        status: ApprovalStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ApprovalRecord]:
        return self.approvals.list(
            project_id=project_id,
            status=status,
            limit=limit,
            offset=offset,
        )

    def count_approvals(
        self,
        project_id: UUID,
        status: ApprovalStatus | None = None,
    ) -> int:
        return self.approvals.count(
            project_id=project_id,
            status=status,
        )

    def save_authorization_with_approval(
        self,
        authorization: AuthorizationResponse,
        approval: ApprovalRecord | None,
        idempotency_record: IdempotencyRecord | None = None,
    ) -> None:
        if (
            approval is not None
            and approval.decision_id
            != authorization.decision_id
        ):
            raise ValueError(
                "Approval decision_id must match "
                "authorization decision_id."
            )

        if idempotency_record is not None:
            if (
                idempotency_record.project_id
                != authorization.project_id
            ):
                raise ValueError(
                    "Idempotency record project_id must match "
                    "authorization project_id."
                )

            if (
                idempotency_record.decision_id
                != authorization.decision_id
            ):
                raise ValueError(
                    "Idempotency record decision_id must match "
                    "authorization decision_id."
                )

        with self.database.connect() as connection:
            self.decisions.insert(
                connection,
                authorization,
            )

            if approval is not None:
                self.approvals.insert(
                    connection,
                    approval,
                )

            if idempotency_record is not None:
                self.idempotency.insert(
                    connection,
                    idempotency_record,
                )

    def save_project_with_api_key(
        self,
        project: Project,
        api_key: ProjectApiKeyRecord,
        policies: list[Policy] | None = None,
    ) -> None:
        if api_key.project_id != project.project_id:
            raise ValueError(
                "API key project_id must match "
                "project project_id."
            )

        with self.database.connect() as connection:
            self.projects.insert(connection, project)
            self.api_keys.insert(connection, api_key)

            for policy in policies or []:
                self.policies.insert_seed(
                    connection=connection,
                    project_id=project.project_id,
                    policy=policy,
                    updated_at=project.created_at,
                )

    def save_project_api_key(
        self,
        api_key: ProjectApiKeyRecord,
    ) -> None:
        self.api_keys.save(api_key)

    def list_project_api_keys(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ProjectApiKeyMetadata]:
        return self.api_keys.list(
            project_id=project_id,
            limit=limit,
            offset=offset,
        )

    def count_project_api_keys(
        self,
        project_id: UUID,
    ) -> int:
        return self.api_keys.count(project_id)

    def revoke_project_api_key(
        self,
        project_id: UUID,
        api_key_id: UUID,
        revoked_at: datetime,
    ) -> ProjectApiKeyMetadata | None:
        return self.api_keys.revoke(
            project_id=project_id,
            api_key_id=api_key_id,
            revoked_at=revoked_at,
        )

    def get_active_project_by_api_key_hash(
        self,
        key_hash: str,
    ) -> Project | None:
        return self.api_keys.get_active_project_by_hash(
            key_hash
        )

    def seed_project_policies(
        self,
        project_id: UUID,
        policies: list[Policy],
        seeded_at: datetime,
    ) -> None:
        self.policies.seed(
            project_id=project_id,
            policies=policies,
            seeded_at=seeded_at,
        )

    def list_project_policy_configurations(
        self,
        project_id: UUID,
    ) -> list[ProjectPolicyConfiguration]:
        return self.policies.list_configurations(project_id)

    def list_project_policies(
        self,
        project_id: UUID,
    ) -> list[Policy]:
        return self.policies.list_active(project_id)

    def get_project_policy_configuration(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> ProjectPolicyConfiguration | None:
        return self.policies.get_configuration(
            project_id=project_id,
            policy_id=policy_id,
        )

    def get_project_policy(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> Policy | None:
        return self.policies.get_active(
            project_id=project_id,
            policy_id=policy_id,
        )

    def save_project_policy(
        self,
        project_id: UUID,
        policy: Policy,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration:
        return self.policies.save(
            project_id=project_id,
            policy=policy,
            updated_at=updated_at,
        )

    def disable_project_policy(
        self,
        project_id: UUID,
        policy_id: str,
        updated_at: datetime,
    ) -> ProjectPolicyConfiguration | None:
        return self.policies.disable(
            project_id=project_id,
            policy_id=policy_id,
            updated_at=updated_at,
        )


__all__ = ["EvidenceStore"]

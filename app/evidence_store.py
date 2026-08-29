from datetime import datetime
from pathlib import Path
from uuid import UUID

from app.api_keys import (
    ProjectApiKeyMetadata,
    ProjectApiKeyRecord,
)
from app.audit import build_audit_event
from app.audit_models import (
    AdministrativeAuditEvent,
    AuditAction,
    AuditActorType,
    AuditContext,
    AuditResourceType,
)
from app.approval_models import (
    ApprovalRecord,
    ApprovalResolutionStatus,
    ApprovalStatus,
)
from app.authorization_models import AuthorizationResponse
from app.idempotency import IdempotencyRecord
from app.integrity_models import (
    DecisionIntegrityProof,
    DecisionIntegrityVerification,
)
from app.policy_models import (
    Policy,
    ProjectPolicyConfiguration,
    ProjectPolicyVersion,
)
from app.project_models import Project, ProjectStatus
from app.storage.api_keys import ProjectApiKeyRepository
from app.storage.audit import AdministrativeAuditRepository
from app.storage.approvals import ApprovalRepository
from app.storage.database import SQLiteDatabase
from app.storage.decisions import (
    AuthorizationDecisionRepository,
)
from app.storage.idempotency import IdempotencyRepository
from app.storage.integrity import DecisionIntegrityRepository
from app.storage.policies import ProjectPolicyRepository
from app.storage.projects import ProjectRepository


class EvidenceStore:
    """Compatibility facade over domain-specific repositories."""

    def __init__(self, database_path: Path) -> None:
        self.database = SQLiteDatabase(database_path)
        self.projects = ProjectRepository(self.database)
        self.api_keys = ProjectApiKeyRepository(self.database)
        self.audit = AdministrativeAuditRepository(self.database)
        self.policies = ProjectPolicyRepository(self.database)
        self.decisions = AuthorizationDecisionRepository(
            self.database
        )
        self.integrity = DecisionIntegrityRepository(
            self.database
        )
        self.approvals = ApprovalRepository(self.database)
        self.idempotency = IdempotencyRepository(self.database)

    @property
    def database_path(self) -> Path:
        return self.database.database_path

    def initialize(self) -> None:
        self.database.initialize()
        self.integrity.backfill_existing_decisions()

    def get_administrative_audit_event(
        self,
        event_id: UUID,
    ) -> AdministrativeAuditEvent | None:
        return self.audit.get(event_id)

    def list_administrative_audit_events(
        self,
        *,
        project_id: UUID | None = None,
        action: AuditAction | None = None,
        resource_type: AuditResourceType | None = None,
        resource_id: str | None = None,
        actor_type: AuditActorType | None = None,
        actor_id: str | None = None,
        occurred_after: datetime | None = None,
        occurred_before: datetime | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[AdministrativeAuditEvent]:
        return self.audit.list(
            project_id=project_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_after=occurred_after,
            occurred_before=occurred_before,
            limit=limit,
            offset=offset,
        )

    def count_administrative_audit_events(
        self,
        *,
        project_id: UUID | None = None,
        action: AuditAction | None = None,
        resource_type: AuditResourceType | None = None,
        resource_id: str | None = None,
        actor_type: AuditActorType | None = None,
        actor_id: str | None = None,
        occurred_after: datetime | None = None,
        occurred_before: datetime | None = None,
    ) -> int:
        return self.audit.count(
            project_id=project_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=actor_type,
            actor_id=actor_id,
            occurred_after=occurred_after,
            occurred_before=occurred_before,
        )

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
        audit_context: AuditContext | None = None,
    ) -> Project | None:
        with self.database.connect() as connection:
            previous = self.projects.get_with_connection(
                connection=connection,
                project_id=project_id,
            )
            updated = self.projects.update_status_with_connection(
                connection=connection,
                project_id=project_id,
                status=status,
                updated_at=updated_at,
            )

            if (
                audit_context is not None
                and previous is not None
                and updated is not None
                and previous.status != updated.status
            ):
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=updated_at,
                        project_id=project_id,
                        context=audit_context,
                        action="PROJECT_STATUS_CHANGED",
                        resource_type="PROJECT",
                        resource_id=str(project_id),
                        before=previous,
                        after=updated,
                    ),
                )

            return updated

    def save(
        self,
        authorization: AuthorizationResponse,
    ) -> None:
        with self.database.connect() as connection:
            self.decisions.insert(
                connection,
                authorization,
            )
            self.integrity.insert(
                connection,
                authorization,
            )

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

    def get_decision_integrity(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> DecisionIntegrityProof | None:
        return self.integrity.get(
            decision_id=decision_id,
            project_id=project_id,
        )

    def list_decision_integrity_records(
        self,
        project_id: UUID,
        limit: int = 20,
        offset: int = 0,
    ) -> list[DecisionIntegrityProof]:
        return self.integrity.list(
            project_id=project_id,
            limit=limit,
            offset=offset,
        )

    def count_decision_integrity_records(
        self,
        project_id: UUID,
    ) -> int:
        return self.integrity.count(project_id)

    def verify_decision_integrity(
        self,
        project_id: UUID,
        expected_head_hash: str | None = None,
    ) -> DecisionIntegrityVerification:
        return self.integrity.verify(
            project_id=project_id,
            expected_head_hash=expected_head_hash,
        )

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
        audit_context: AuditContext | None = None,
    ) -> ApprovalRecord:
        with self.database.connect() as connection:
            previous = self.approvals.get_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
            )
            resolved = self.approvals.resolve_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
                status=status,
                resolved_by=resolved_by,
                resolved_at=resolved_at,
            )

            if audit_context is not None:
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=resolved_at,
                        project_id=project_id,
                        context=audit_context,
                        action="APPROVAL_RESOLVED",
                        resource_type="APPROVAL",
                        resource_id=str(decision_id),
                        before=previous,
                        after=resolved,
                        metadata={"resolution": status},
                    ),
                )

            return resolved

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
            self.integrity.insert(
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
        audit_context: AuditContext | None = None,
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

            if audit_context is not None:
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=project.created_at,
                        project_id=project.project_id,
                        context=audit_context,
                        action="PROJECT_CREATED",
                        resource_type="PROJECT",
                        resource_id=str(project.project_id),
                        after=project,
                        metadata={
                            "seeded_policy_count": len(
                                policies or []
                            ),
                        },
                    ),
                )
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=api_key.created_at,
                        project_id=project.project_id,
                        context=audit_context,
                        action="API_KEY_CREATED",
                        resource_type="API_KEY",
                        resource_id=str(api_key.api_key_id),
                        after=ProjectApiKeyMetadata(
                            api_key_id=api_key.api_key_id,
                            project_id=api_key.project_id,
                            key_prefix=api_key.key_prefix,
                            created_at=api_key.created_at,
                            revoked_at=api_key.revoked_at,
                        ),
                    ),
                )

                for policy in policies or []:
                    configuration = ProjectPolicyConfiguration(
                        project_id=project.project_id,
                        policy=policy,
                        enabled=True,
                        updated_at=project.created_at,
                    )
                    self.audit.insert(
                        connection,
                        build_audit_event(
                            occurred_at=project.created_at,
                            project_id=project.project_id,
                            context=audit_context,
                            action="POLICY_CREATED",
                            resource_type="POLICY",
                            resource_id=policy.id,
                            after=configuration,
                            metadata={"source": "template"},
                        ),
                    )

    def save_project_api_key(
        self,
        api_key: ProjectApiKeyRecord,
        audit_context: AuditContext | None = None,
    ) -> None:
        with self.database.connect() as connection:
            self.api_keys.insert(connection, api_key)

            if audit_context is not None:
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=api_key.created_at,
                        project_id=api_key.project_id,
                        context=audit_context,
                        action="API_KEY_CREATED",
                        resource_type="API_KEY",
                        resource_id=str(api_key.api_key_id),
                        after=ProjectApiKeyMetadata(
                            api_key_id=api_key.api_key_id,
                            project_id=api_key.project_id,
                            key_prefix=api_key.key_prefix,
                            created_at=api_key.created_at,
                            revoked_at=api_key.revoked_at,
                        ),
                    ),
                )

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
        audit_context: AuditContext | None = None,
    ) -> ProjectApiKeyMetadata | None:
        with self.database.connect() as connection:
            previous = self.api_keys.get_metadata_with_connection(
                connection=connection,
                project_id=project_id,
                api_key_id=api_key_id,
            )
            revoked = self.api_keys.revoke_with_connection(
                connection=connection,
                project_id=project_id,
                api_key_id=api_key_id,
                revoked_at=revoked_at,
            )

            if (
                audit_context is not None
                and previous is not None
                and previous.revoked_at is None
                and revoked is not None
            ):
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=revoked_at,
                        project_id=project_id,
                        context=audit_context,
                        action="API_KEY_REVOKED",
                        resource_type="API_KEY",
                        resource_id=str(api_key_id),
                        before=previous,
                        after=revoked,
                    ),
                )

            return revoked

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
        audit_context: AuditContext | None = None,
    ) -> None:
        with self.database.connect() as connection:
            for policy in policies:
                previous = (
                    self.policies
                    .get_configuration_with_connection(
                        connection=connection,
                        project_id=project_id,
                        policy_id=policy.id,
                    )
                )
                self.policies.insert_seed(
                    connection=connection,
                    project_id=project_id,
                    policy=policy,
                    updated_at=seeded_at,
                )

                if (
                    audit_context is not None
                    and previous is None
                ):
                    created = (
                        self.policies
                        .get_configuration_with_connection(
                            connection=connection,
                            project_id=project_id,
                            policy_id=policy.id,
                        )
                    )
                    self.audit.insert(
                        connection,
                        build_audit_event(
                            occurred_at=seeded_at,
                            project_id=project_id,
                            context=audit_context,
                            action="POLICY_CREATED",
                            resource_type="POLICY",
                            resource_id=policy.id,
                            after=created,
                            metadata={"source": "template"},
                        ),
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
        audit_context: AuditContext | None = None,
    ) -> ProjectPolicyConfiguration:
        with self.database.connect() as connection:
            previous = (
                self.policies.get_configuration_with_connection(
                    connection=connection,
                    project_id=project_id,
                    policy_id=policy.id,
                )
            )
            saved = self.policies.save_with_connection(
                connection=connection,
                project_id=project_id,
                policy=policy,
                updated_at=updated_at,
            )

            if audit_context is not None:
                action: AuditAction = (
                    "POLICY_CREATED"
                    if previous is None
                    else "POLICY_UPDATED"
                )
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=updated_at,
                        project_id=project_id,
                        context=audit_context,
                        action=action,
                        resource_type="POLICY",
                        resource_id=policy.id,
                        before=previous,
                        after=saved,
                        metadata={
                            "new_version": saved.policy.version,
                            "previous_version": (
                                previous.policy.version
                                if previous is not None
                                else None
                            ),
                        },
                    ),
                )

            return saved

    def list_project_policy_versions(
        self,
        project_id: UUID,
        policy_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ProjectPolicyVersion]:
        return self.policies.list_versions(
            project_id=project_id,
            policy_id=policy_id,
            limit=limit,
            offset=offset,
        )

    def count_project_policy_versions(
        self,
        project_id: UUID,
        policy_id: str,
    ) -> int:
        return self.policies.count_versions(
            project_id=project_id,
            policy_id=policy_id,
        )

    def get_project_policy_version(
        self,
        project_id: UUID,
        policy_id: str,
        version: int,
    ) -> ProjectPolicyVersion | None:
        return self.policies.get_version(
            project_id=project_id,
            policy_id=policy_id,
            version=version,
        )

    def rollback_project_policy(
        self,
        project_id: UUID,
        policy_id: str,
        source_version: int,
        updated_at: datetime,
        audit_context: AuditContext | None = None,
    ) -> ProjectPolicyConfiguration:
        with self.database.connect() as connection:
            previous = (
                self.policies.get_configuration_with_connection(
                    connection=connection,
                    project_id=project_id,
                    policy_id=policy_id,
                )
            )
            restored = self.policies.rollback_with_connection(
                connection=connection,
                project_id=project_id,
                policy_id=policy_id,
                source_version=source_version,
                updated_at=updated_at,
            )

            if audit_context is not None:
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=updated_at,
                        project_id=project_id,
                        context=audit_context,
                        action="POLICY_ROLLED_BACK",
                        resource_type="POLICY",
                        resource_id=policy_id,
                        before=previous,
                        after=restored,
                        metadata={
                            "source_version": source_version,
                            "new_version": restored.policy.version,
                        },
                    ),
                )

            return restored

    def disable_project_policy(
        self,
        project_id: UUID,
        policy_id: str,
        updated_at: datetime,
        audit_context: AuditContext | None = None,
    ) -> ProjectPolicyConfiguration | None:
        with self.database.connect() as connection:
            previous = (
                self.policies.get_configuration_with_connection(
                    connection=connection,
                    project_id=project_id,
                    policy_id=policy_id,
                )
            )
            disabled = self.policies.disable_with_connection(
                connection=connection,
                project_id=project_id,
                policy_id=policy_id,
                updated_at=updated_at,
            )

            if (
                audit_context is not None
                and previous is not None
                and previous.enabled
                and disabled is not None
            ):
                self.audit.insert(
                    connection,
                    build_audit_event(
                        occurred_at=updated_at,
                        project_id=project_id,
                        context=audit_context,
                        action="POLICY_DISABLED",
                        resource_type="POLICY",
                        resource_id=policy_id,
                        before=previous,
                        after=disabled,
                    ),
                )

            return disabled


__all__ = ["EvidenceStore"]

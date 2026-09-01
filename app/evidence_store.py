import secrets
import sqlite3
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from app.api_keys import (
    ProjectApiKeyMetadata,
    ProjectApiKeyPrincipal,
    ProjectApiKeyRecord,
)
from app.approval_models import (
    ApprovalRecord,
    ApprovalResolutionStatus,
    ApprovalStatus,
)
from app.audit import build_audit_event
from app.audit_models import (
    AdministrativeAuditEvent,
    AuditAction,
    AuditActorType,
    AuditContext,
    AuditResourceType,
)
from app.authorization_models import AuthorizationResponse
from app.evidence_models import (
    DecisionSearchFilters,
    EvidenceExportSnapshot,
)
from app.exceptions import (
    ApprovalAlreadyResolvedError,
    ApprovalExpiredError,
    ApprovalNotFoundError,
    ExecutionGrantAlreadyConsumedError,
    ExecutionGrantExpiredError,
    ExecutionGrantMismatchError,
    InvalidExecutionGrantError,
)
from app.execution_models import (
    ExecutionGrantPayload,
    ExecutionGrantRecord,
)
from app.idempotency import IdempotencyRecord
from app.integrity_models import (
    DecisionIntegrityProof,
    DecisionIntegrityVerification,
    VerifiableDecisionRecord,
)
from app.policy_models import (
    Policy,
    ProjectPolicyConfiguration,
    ProjectPolicyVersion,
)
from app.project_models import Project, ProjectStatus
from app.storage.api_keys import ProjectApiKeyRepository
from app.storage.approvals import ApprovalRepository
from app.storage.audit import AdministrativeAuditRepository
from app.storage.database import SQLiteDatabase
from app.storage.decisions import (
    AuthorizationDecisionRepository,
)
from app.storage.evidence import EvidenceRepository
from app.storage.execution_grants import ExecutionGrantRepository
from app.storage.idempotency import IdempotencyRepository
from app.storage.integrity import DecisionIntegrityRepository
from app.storage.policies import ProjectPolicyRepository
from app.storage.projects import ProjectRepository
from app.storage.webhooks import (
    WebhookDispatchItem,
    WebhookRepository,
)
from app.webhook_models import (
    WebhookDelivery,
    WebhookDeliveryAttempt,
    WebhookDeliveryOutcome,
    WebhookDeliveryStatus,
    WebhookEvent,
    WebhookEventType,
    WebhookSubscription,
    WebhookSubscriptionStatus,
)
from app.webhooks import (
    build_webhook_event,
    build_webhook_event_from_audit,
)


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
        self.evidence_exports = EvidenceRepository(self.database)
        self.integrity = DecisionIntegrityRepository(
            self.database
        )
        self.approvals = ApprovalRepository(self.database)
        self.execution_grants = ExecutionGrantRepository(
            self.database
        )
        self.idempotency = IdempotencyRepository(self.database)
        self.webhooks = WebhookRepository(self.database)

    @property
    def database_path(self) -> Path:
        return self.database.database_path

    def initialize(self) -> None:
        self.database.initialize()
        self.integrity.backfill_existing_decisions()

    def check_readiness(self) -> bool:
        return self.database.check_readiness()

    def _enqueue_webhook_event(
        self,
        connection: sqlite3.Connection,
        event: WebhookEvent,
    ) -> None:
        if self.projects.get_with_connection(
            connection=connection,
            project_id=event.project_id,
        ) is None:
            return

        self.webhooks.insert_event_with_deliveries(
            connection,
            event,
        )

    def _record_administrative_change(
        self,
        connection: sqlite3.Connection,
        event: AdministrativeAuditEvent,
    ) -> None:
        self.audit.insert(connection, event)
        self._enqueue_webhook_event(
            connection,
            build_webhook_event_from_audit(event),
        )

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
                self._record_administrative_change(
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
            self._enqueue_webhook_event(
                connection,
                build_webhook_event(
                    project_id=authorization.project_id,
                    event_type="authorization.created",
                    occurred_at=authorization.evaluated_at,
                    resource_type="AUTHORIZATION_DECISION",
                    resource_id=str(
                        authorization.decision_id
                    ),
                    data={
                        "authorization": (
                            authorization.model_dump(
                                mode="json"
                            )
                        ),
                    },
                ),
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

    def search_decisions(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        limit: int = 20,
        offset: int = 0,
    ) -> list[AuthorizationResponse]:
        self.expire_due_approvals(project_id=project_id)
        return self.decisions.search(
            project_id=project_id,
            filters=filters,
            limit=limit,
            offset=offset,
        )

    def count_searched_decisions(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
    ) -> int:
        self.expire_due_approvals(project_id=project_id)
        return self.decisions.count_search(
            project_id=project_id,
            filters=filters,
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

    def create_evidence_export_snapshot(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
    ) -> EvidenceExportSnapshot:
        return self.evidence_exports.create_snapshot(
            project_id=project_id,
            filters=filters,
        )

    def capture_evidence_export_records(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        maximum_records: int,
        maximum_bytes: int,
    ) -> tuple[
        EvidenceExportSnapshot,
        list[VerifiableDecisionRecord],
    ]:
        self.expire_due_approvals(project_id=project_id)
        return self.evidence_exports.capture_records(
            project_id=project_id,
            filters=filters,
            maximum_records=maximum_records,
            maximum_bytes=maximum_bytes,
        )

    def iter_evidence_records(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        max_sequence_number: int,
    ) -> Iterator[VerifiableDecisionRecord]:
        return self.evidence_exports.iter_records(
            project_id=project_id,
            filters=filters,
            max_sequence_number=max_sequence_number,
        )

    def list_evidence_records(
        self,
        *,
        project_id: UUID,
        filters: DecisionSearchFilters,
        max_sequence_number: int,
        maximum_bytes: int = 32 * 1024 * 1024,
    ) -> list[VerifiableDecisionRecord]:
        return self.evidence_exports.list_records(
            project_id=project_id,
            filters=filters,
            max_sequence_number=max_sequence_number,
            maximum_bytes=maximum_bytes,
        )

    def list_evidence_chain(
        self,
        *,
        project_id: UUID,
        max_sequence_number: int,
        maximum_bytes: int = 32 * 1024 * 1024,
    ) -> list[DecisionIntegrityProof]:
        return self.evidence_exports.list_chain(
            project_id=project_id,
            max_sequence_number=max_sequence_number,
            maximum_bytes=maximum_bytes,
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

    def expire_due_approvals(
        self,
        *,
        project_id: UUID,
        expired_at: datetime | None = None,
    ) -> list[ApprovalRecord]:
        effective_time = expired_at or datetime.now(timezone.utc)

        with self.database.connect() as connection:
            expired_pairs = (
                self.approvals.expire_due_with_connection(
                    connection=connection,
                    project_id=project_id,
                    expired_at=effective_time,
                )
            )

            for previous, expired in expired_pairs:
                self._record_administrative_change(
                    connection,
                    build_audit_event(
                        occurred_at=effective_time,
                        project_id=project_id,
                        context=AuditContext(
                            actor_type="SYSTEM",
                            actor_id="decaustrum-expiration",
                            reason=(
                                "Approval validity period elapsed."
                            ),
                        ),
                        action="APPROVAL_EXPIRED",
                        resource_type="APPROVAL",
                        resource_id=str(expired.decision_id),
                        before=previous,
                        after=expired,
                        metadata={
                            "expires_at": (
                                expired.expires_at.isoformat()
                                if expired.expires_at is not None
                                else None
                            ),
                        },
                    ),
                )

        return [current for _, current in expired_pairs]

    def get_approval(
        self,
        decision_id: UUID,
        project_id: UUID,
    ) -> ApprovalRecord | None:
        self.expire_due_approvals(project_id=project_id)
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
        self.expire_due_approvals(
            project_id=project_id,
            expired_at=resolved_at,
        )

        if status == "APPROVED":
            raise ValueError(
                "Approvals must be approved with an execution grant."
            )

        with self.database.connect() as connection:
            previous = self.approvals.get_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
            )

            if previous is not None and previous.status == "EXPIRED":
                raise ApprovalExpiredError(decision_id)

            resolved = self.approvals.resolve_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
                status=status,
                resolved_by=resolved_by,
                resolved_at=resolved_at,
            )

            if audit_context is not None:
                self._record_administrative_change(
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

    def approve_approval_with_grant(
        self,
        *,
        decision_id: UUID,
        project_id: UUID,
        resolved_by: str,
        resolved_at: datetime,
        grant: ExecutionGrantRecord,
        audit_context: AuditContext,
    ) -> tuple[ApprovalRecord, ExecutionGrantRecord]:
        self.expire_due_approvals(
            project_id=project_id,
            expired_at=resolved_at,
        )

        if (
            grant.decision_id != decision_id
            or grant.project_id != project_id
        ):
            raise ValueError(
                "Execution grant scope must match the approval."
            )

        with self.database.connect() as connection:
            previous = self.approvals.get_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
            )

            if previous is None:
                raise ApprovalNotFoundError(decision_id)

            if previous.status == "EXPIRED":
                raise ApprovalExpiredError(decision_id)

            if previous.status == "APPROVED":
                existing_grant = (
                    self.execution_grants
                    .get_by_decision_with_connection(
                        connection=connection,
                        decision_id=decision_id,
                        project_id=project_id,
                    )
                )

                if existing_grant is None:
                    raise RuntimeError(
                        "Approved request has no execution grant."
                    )

                return previous, existing_grant

            if previous.status != "PENDING":
                raise ApprovalAlreadyResolvedError(
                    decision_id=decision_id,
                    current_status=previous.status,
                )

            authorization = self.decisions.get_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
            )

            if (
                authorization is None
                or authorization.decision != "REQUIRE_APPROVAL"
            ):
                raise RuntimeError(
                    "Approval references an invalid authorization."
                )

            self.execution_grants.insert(connection, grant)
            approved = self.approvals.resolve_with_connection(
                connection=connection,
                decision_id=decision_id,
                project_id=project_id,
                status="APPROVED",
                resolved_by=resolved_by,
                resolved_at=resolved_at,
            )
            self._record_administrative_change(
                connection,
                build_audit_event(
                    occurred_at=resolved_at,
                    project_id=project_id,
                    context=audit_context,
                    action="APPROVAL_RESOLVED",
                    resource_type="APPROVAL",
                    resource_id=str(decision_id),
                    before=previous,
                    after=approved,
                    metadata={"resolution": "APPROVED"},
                ),
            )
            self._record_administrative_change(
                connection,
                build_audit_event(
                    occurred_at=grant.issued_at,
                    project_id=project_id,
                    context=audit_context,
                    action="EXECUTION_GRANT_ISSUED",
                    resource_type="EXECUTION_GRANT",
                    resource_id=str(grant.grant_id),
                    after=grant,
                    metadata={
                        "decision_id": str(decision_id),
                        "expires_at": grant.expires_at.isoformat(),
                    },
                ),
            )

            return approved, grant

    def get_execution_grant(
        self,
        *,
        grant_id: UUID,
        project_id: UUID,
    ) -> ExecutionGrantRecord | None:
        return self.execution_grants.get(
            grant_id=grant_id,
            project_id=project_id,
        )

    def get_execution_grant_for_decision(
        self,
        *,
        decision_id: UUID,
        project_id: UUID,
    ) -> ExecutionGrantRecord | None:
        return self.execution_grants.get_by_decision(
            decision_id=decision_id,
            project_id=project_id,
        )

    def consume_execution_grant(
        self,
        *,
        payload: ExecutionGrantPayload,
        project_id: UUID,
        token_hash: str,
        request_fingerprint: str,
        consumed_at: datetime,
        consumed_by: str,
        audit_context: AuditContext,
    ) -> ExecutionGrantRecord:
        if payload.project_id != project_id:
            raise InvalidExecutionGrantError()

        expiration_error: ExecutionGrantExpiredError | None = None
        consumed: ExecutionGrantRecord | None = None

        with self.database.connect() as connection:
            current = self.execution_grants.get_with_connection(
                connection=connection,
                grant_id=payload.grant_id,
                project_id=project_id,
            )

            if current is None or not secrets.compare_digest(
                current.token_hash,
                token_hash,
            ):
                raise InvalidExecutionGrantError()

            if (
                current.decision_id != payload.decision_id
                or current.project_id != payload.project_id
                or current.issued_at != payload.issued_at
                or current.expires_at != payload.expires_at
                or not secrets.compare_digest(
                    current.request_fingerprint,
                    payload.request_fingerprint,
                )
            ):
                raise InvalidExecutionGrantError()

            if not secrets.compare_digest(
                current.request_fingerprint,
                request_fingerprint,
            ):
                raise ExecutionGrantMismatchError(
                    payload.grant_id
                )

            if current.status == "CONSUMED":
                raise ExecutionGrantAlreadyConsumedError(
                    payload.grant_id
                )

            if current.status == "EXPIRED":
                raise ExecutionGrantExpiredError(payload.grant_id)

            if current.expires_at <= consumed_at:
                expired = (
                    self.execution_grants.expire_with_connection(
                        connection=connection,
                        grant_id=payload.grant_id,
                        project_id=project_id,
                        expired_at=consumed_at,
                    )
                )

                if expired is None:
                    raise RuntimeError(
                        "Execution grant expiration failed."
                    )

                self._record_administrative_change(
                    connection,
                    build_audit_event(
                        occurred_at=consumed_at,
                        project_id=project_id,
                        context=AuditContext(
                            actor_type="SYSTEM",
                            actor_id="decaustrum-expiration",
                            reason=(
                                "Execution grant validity period "
                                "elapsed."
                            ),
                        ),
                        action="EXECUTION_GRANT_EXPIRED",
                        resource_type="EXECUTION_GRANT",
                        resource_id=str(payload.grant_id),
                        before=current,
                        after=expired,
                        metadata={
                            "decision_id": str(payload.decision_id),
                        },
                    ),
                )
                expiration_error = ExecutionGrantExpiredError(
                    payload.grant_id
                )
            else:
                consumed = (
                    self.execution_grants.consume_with_connection(
                        connection=connection,
                        grant_id=payload.grant_id,
                        project_id=project_id,
                        token_hash=token_hash,
                        consumed_at=consumed_at,
                        consumed_by=consumed_by,
                    )
                )

                if consumed is None:
                    latest = (
                        self.execution_grants.get_with_connection(
                            connection=connection,
                            grant_id=payload.grant_id,
                            project_id=project_id,
                        )
                    )

                    if latest is None:
                        raise InvalidExecutionGrantError()

                    if latest.status == "CONSUMED":
                        raise ExecutionGrantAlreadyConsumedError(
                            payload.grant_id
                        )

                    if latest.status == "EXPIRED":
                        raise ExecutionGrantExpiredError(
                            payload.grant_id
                        )

                    raise RuntimeError(
                        "Execution grant atomic update failed."
                    )

                self._record_administrative_change(
                    connection,
                    build_audit_event(
                        occurred_at=consumed_at,
                        project_id=project_id,
                        context=audit_context,
                        action="EXECUTION_GRANT_CONSUMED",
                        resource_type="EXECUTION_GRANT",
                        resource_id=str(payload.grant_id),
                        before=current,
                        after=consumed,
                        metadata={
                            "decision_id": str(payload.decision_id),
                        },
                    ),
                )

        if expiration_error is not None:
            raise expiration_error

        if consumed is None:
            raise RuntimeError("Execution grant was not consumed.")

        return consumed

    def list_approvals(
        self,
        project_id: UUID,
        status: ApprovalStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ApprovalRecord]:
        self.expire_due_approvals(project_id=project_id)
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
        self.expire_due_approvals(project_id=project_id)
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

            self._enqueue_webhook_event(
                connection,
                build_webhook_event(
                    project_id=authorization.project_id,
                    event_type="authorization.created",
                    occurred_at=authorization.evaluated_at,
                    resource_type="AUTHORIZATION_DECISION",
                    resource_id=str(
                        authorization.decision_id
                    ),
                    data={
                        "authorization": (
                            authorization.model_dump(
                                mode="json"
                            )
                        ),
                    },
                ),
            )

            if approval is not None:
                self._enqueue_webhook_event(
                    connection,
                    build_webhook_event(
                        project_id=authorization.project_id,
                        event_type="approval.requested",
                        occurred_at=approval.requested_at,
                        resource_type="APPROVAL",
                        resource_id=str(approval.decision_id),
                        data={
                            "approval": approval.model_dump(
                                mode="json"
                            ),
                        },
                    ),
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
                self._record_administrative_change(
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
                self._record_administrative_change(
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
                            role=api_key.role,
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
                    self._record_administrative_change(
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
                self._record_administrative_change(
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
                            role=api_key.role,
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
                self._record_administrative_change(
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

    def get_active_api_key_principal_by_hash(
        self,
        key_hash: str,
    ) -> ProjectApiKeyPrincipal | None:
        return self.api_keys.get_active_principal_by_hash(key_hash)

    def save_webhook_subscription(
        self,
        subscription: WebhookSubscription,
        audit_context: AuditContext,
    ) -> None:
        with self.database.connect() as connection:
            self.webhooks.insert_subscription(
                connection,
                subscription,
            )
            self._record_administrative_change(
                connection,
                build_audit_event(
                    occurred_at=subscription.created_at,
                    project_id=subscription.project_id,
                    context=audit_context,
                    action="WEBHOOK_SUBSCRIPTION_CREATED",
                    resource_type="WEBHOOK_SUBSCRIPTION",
                    resource_id=str(
                        subscription.subscription_id
                    ),
                    after=subscription,
                ),
            )

    def get_webhook_subscription(
        self,
        project_id: UUID,
        subscription_id: UUID,
    ) -> WebhookSubscription | None:
        return self.webhooks.get_subscription(
            project_id,
            subscription_id,
        )

    def list_webhook_subscriptions(
        self,
        project_id: UUID,
        status: WebhookSubscriptionStatus | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookSubscription]:
        return self.webhooks.list_subscriptions(
            project_id=project_id,
            status=status,
            limit=limit,
            offset=offset,
        )

    def count_webhook_subscriptions(
        self,
        project_id: UUID,
        status: WebhookSubscriptionStatus | None = None,
    ) -> int:
        return self.webhooks.count_subscriptions(
            project_id=project_id,
            status=status,
        )

    def disable_webhook_subscription(
        self,
        *,
        project_id: UUID,
        subscription_id: UUID,
        disabled_at: datetime,
        audit_context: AuditContext,
    ) -> WebhookSubscription:
        with self.database.connect() as connection:
            previous = (
                self.webhooks
                .get_subscription_with_connection(
                    connection,
                    project_id,
                    subscription_id,
                )
            )
            disabled = (
                self.webhooks
                .disable_subscription_with_connection(
                    connection,
                    project_id,
                    subscription_id,
                    disabled_at,
                )
            )

            if (
                previous is not None
                and previous.status == "ACTIVE"
            ):
                self._record_administrative_change(
                    connection,
                    build_audit_event(
                        occurred_at=disabled_at,
                        project_id=project_id,
                        context=audit_context,
                        action=(
                            "WEBHOOK_SUBSCRIPTION_DISABLED"
                        ),
                        resource_type=(
                            "WEBHOOK_SUBSCRIPTION"
                        ),
                        resource_id=str(subscription_id),
                        before=previous,
                        after=disabled,
                    ),
                )

            return disabled

    def rotate_webhook_secret(
        self,
        *,
        project_id: UUID,
        subscription_id: UUID,
        rotated_at: datetime,
        audit_context: AuditContext,
    ) -> WebhookSubscription:
        with self.database.connect() as connection:
            previous = (
                self.webhooks
                .get_subscription_with_connection(
                    connection,
                    project_id,
                    subscription_id,
                )
            )
            rotated = (
                self.webhooks
                .rotate_subscription_secret_with_connection(
                    connection,
                    project_id,
                    subscription_id,
                    rotated_at,
                )
            )
            self._record_administrative_change(
                connection,
                build_audit_event(
                    occurred_at=rotated_at,
                    project_id=project_id,
                    context=audit_context,
                    action="WEBHOOK_SECRET_ROTATED",
                    resource_type="WEBHOOK_SUBSCRIPTION",
                    resource_id=str(subscription_id),
                    before=previous,
                    after=rotated,
                    metadata={
                        "secret_version": rotated.secret_version,
                    },
                ),
            )

            return rotated

    def get_webhook_event(
        self,
        project_id: UUID,
        event_id: UUID,
    ) -> WebhookEvent | None:
        return self.webhooks.get_event(project_id, event_id)

    def list_webhook_events(
        self,
        project_id: UUID,
        event_type: WebhookEventType | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookEvent]:
        return self.webhooks.list_events(
            project_id=project_id,
            event_type=event_type,
            limit=limit,
            offset=offset,
        )

    def count_webhook_events(
        self,
        project_id: UUID,
        event_type: WebhookEventType | None = None,
    ) -> int:
        return self.webhooks.count_events(
            project_id=project_id,
            event_type=event_type,
        )

    def get_webhook_delivery(
        self,
        project_id: UUID,
        delivery_id: UUID,
    ) -> WebhookDelivery | None:
        return self.webhooks.get_delivery(
            project_id,
            delivery_id,
        )

    def list_webhook_deliveries(
        self,
        *,
        project_id: UUID,
        status: WebhookDeliveryStatus | None = None,
        subscription_id: UUID | None = None,
        event_id: UUID | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[WebhookDelivery]:
        return self.webhooks.list_deliveries(
            project_id=project_id,
            status=status,
            subscription_id=subscription_id,
            event_id=event_id,
            limit=limit,
            offset=offset,
        )

    def count_webhook_deliveries(
        self,
        *,
        project_id: UUID,
        status: WebhookDeliveryStatus | None = None,
        subscription_id: UUID | None = None,
        event_id: UUID | None = None,
    ) -> int:
        return self.webhooks.count_deliveries(
            project_id=project_id,
            status=status,
            subscription_id=subscription_id,
            event_id=event_id,
        )

    def list_webhook_delivery_attempts(
        self,
        delivery_id: UUID,
    ) -> list[WebhookDeliveryAttempt]:
        return self.webhooks.list_attempts(delivery_id)

    def claim_due_webhook_deliveries(
        self,
        *,
        now: datetime,
        limit: int,
        lease_seconds: int,
    ) -> list[WebhookDelivery]:
        return self.webhooks.claim_due_deliveries(
            now=now,
            limit=limit,
            lease_seconds=lease_seconds,
        )

    def get_webhook_dispatch_item(
        self,
        delivery: WebhookDelivery,
    ) -> WebhookDispatchItem:
        return self.webhooks.get_dispatch_item(delivery)

    def cancel_processing_webhook_delivery(
        self,
        *,
        project_id: UUID,
        delivery_id: UUID,
        cancelled_at: datetime,
        reason: str,
    ) -> WebhookDelivery:
        return self.webhooks.cancel_processing_delivery(
            project_id=project_id,
            delivery_id=delivery_id,
            cancelled_at=cancelled_at,
            reason=reason,
        )

    def record_webhook_delivery_result(
        self,
        *,
        project_id: UUID,
        delivery_id: UUID,
        attempted_at: datetime,
        completed_at: datetime,
        outcome: WebhookDeliveryOutcome,
        status_code: int | None,
        error: str | None,
        max_attempts: int,
        base_retry_seconds: int,
        max_retry_seconds: int,
    ) -> WebhookDelivery:
        return self.webhooks.record_delivery_result(
            project_id=project_id,
            delivery_id=delivery_id,
            attempted_at=attempted_at,
            completed_at=completed_at,
            outcome=outcome,
            status_code=status_code,
            error=error,
            max_attempts=max_attempts,
            base_retry_seconds=base_retry_seconds,
            max_retry_seconds=max_retry_seconds,
        )

    def request_webhook_redelivery(
        self,
        *,
        project_id: UUID,
        delivery_id: UUID,
        requested_at: datetime,
        audit_context: AuditContext,
    ) -> WebhookDelivery:
        with self.database.connect() as connection:
            previous = (
                self.webhooks.get_delivery_with_connection(
                    connection,
                    project_id,
                    delivery_id,
                )
            )
            redelivery = (
                self.webhooks
                .request_redelivery_with_connection(
                    connection,
                    project_id=project_id,
                    delivery_id=delivery_id,
                    requested_at=requested_at,
                )
            )
            self._record_administrative_change(
                connection,
                build_audit_event(
                    occurred_at=requested_at,
                    project_id=project_id,
                    context=audit_context,
                    action="WEBHOOK_REDELIVERY_REQUESTED",
                    resource_type="WEBHOOK_DELIVERY",
                    resource_id=str(delivery_id),
                    before=previous,
                    after=redelivery,
                    metadata={
                        "event_id": str(redelivery.event_id),
                        "subscription_id": str(
                            redelivery.subscription_id
                        ),
                    },
                ),
            )

            return redelivery

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
                    self._record_administrative_change(
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
                self._record_administrative_change(
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
                self._record_administrative_change(
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
                self._record_administrative_change(
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

from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException

from app.evidence_store import EvidenceStore
from app.exceptions import PolicyVersionConflictError
from app.policy_models import (
    Policy,
    ProjectPolicyConfiguration,
)
from app.services.projects import get_project_or_404


def get_project_policy_or_404(
    project_id: UUID,
    policy_id: str,
    store: EvidenceStore,
) -> ProjectPolicyConfiguration:
    configuration = (
        store.get_project_policy_configuration(
            project_id=project_id,
            policy_id=policy_id,
        )
    )

    if configuration is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "policy_not_found",
                "message": (
                    f"Policy '{policy_id}' was not found "
                    f"for project '{project_id}'."
                ),
            },
        )

    return configuration


def configure_policy(
    project_id: UUID,
    policy_id: str,
    policy: Policy,
    store: EvidenceStore,
) -> ProjectPolicyConfiguration:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )

    if policy.id != policy_id:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "policy_id_mismatch",
                "message": (
                    f"Policy ID '{policy.id}' does not match "
                    f"path policy ID '{policy_id}'."
                ),
                "path_policy_id": policy_id,
                "body_policy_id": policy.id,
            },
        )

    try:
        return store.save_project_policy(
            project_id=project_id,
            policy=policy,
            updated_at=datetime.now(timezone.utc),
        )
    except PolicyVersionConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "policy_version_conflict",
                "message": str(exc),
                "expected_version": exc.expected_version,
                "provided_version": exc.provided_version,
            },
        ) from exc


def disable_policy(
    project_id: UUID,
    policy_id: str,
    store: EvidenceStore,
) -> ProjectPolicyConfiguration:
    get_project_or_404(
        project_id=project_id,
        store=store,
    )

    configuration = store.disable_project_policy(
        project_id=project_id,
        policy_id=policy_id,
        updated_at=datetime.now(timezone.utc),
    )

    if configuration is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "policy_not_found",
                "message": (
                    f"Policy '{policy_id}' was not found "
                    f"for project '{project_id}'."
                ),
            },
        )

    return configuration

from datetime import datetime
from typing import Annotated

from fastapi import Depends, HTTPException, Query
from pydantic import ValidationError

from app.evidence_models import (
    DecisionSearchFilters,
    DecisionSortOrder,
    EvidenceApprovalStatus,
)
from app.policy_types import Decision


def get_decision_search_filters(
    decision: Decision | None = Query(default=None),
    agent: str | None = Query(
        default=None,
        min_length=1,
        max_length=200,
    ),
    action: str | None = Query(
        default=None,
        min_length=1,
        max_length=200,
    ),
    policy_id: str | None = Query(
        default=None,
        min_length=1,
        max_length=200,
    ),
    has_policy: bool | None = Query(default=None),
    approval_status: EvidenceApprovalStatus | None = Query(
        default=None
    ),
    evaluated_after: datetime | None = Query(default=None),
    evaluated_before: datetime | None = Query(default=None),
    query: str | None = Query(
        default=None,
        min_length=1,
        max_length=200,
    ),
    sort: DecisionSortOrder = Query(default="desc"),
) -> DecisionSearchFilters:
    try:
        return DecisionSearchFilters(
            decision=decision,
            agent=agent,
            action=action,
            policy_id=policy_id,
            has_policy=has_policy,
            approval_status=approval_status,
            evaluated_after=evaluated_after,
            evaluated_before=evaluated_before,
            query=query,
            sort=sort,
        )
    except ValidationError as exc:
        errors = [
            {
                "field": ".".join(
                    str(part) for part in error["loc"]
                ) or "filters",
                "message": error["msg"],
            }
            for error in exc.errors()
        ]
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_decision_search_filters",
                "message": "Decision search filters are invalid.",
                "errors": errors,
            },
        ) from exc


DecisionSearchDependency = Annotated[
    DecisionSearchFilters,
    Depends(get_decision_search_filters),
]


__all__ = [
    "DecisionSearchDependency",
    "get_decision_search_filters",
]

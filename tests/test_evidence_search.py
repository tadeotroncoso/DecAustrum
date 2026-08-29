import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.approval_models import ApprovalRecord
from app.authorization_models import AuthorizationResponse
from app.evidence_models import DecisionSearchFilters
from app.evidence_store import EvidenceStore
from app.services.evidence import prepare_evidence_export


FIRST_PROJECT_ID = UUID(
    "40000000-0000-0000-0000-000000000001"
)
SECOND_PROJECT_ID = UUID(
    "40000000-0000-0000-0000-000000000002"
)
BASE_TIME = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def authorization(
    *,
    index: int,
    project_id: UUID = FIRST_PROJECT_ID,
    decision: str = "ALLOW",
    agent: str = "support-agent",
    action: str = "read_ticket",
    policy_id: str | None = None,
    reason: str = "No policy matched.",
) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision_id=UUID(
            f"50000000-0000-0000-{project_id.int % 10000:04d}-"
            f"{index:012d}"
        ),
        project_id=project_id,
        evaluated_at=BASE_TIME + timedelta(minutes=index),
        decision=decision,
        policy=policy_id,
        policy_version=1 if policy_id is not None else None,
        reason=reason,
        evidence=None,
        agent=agent,
        action=action,
        context={"index": index},
        trace=[],
    )


def seeded_store(tmp_path) -> tuple[EvidenceStore, list]:
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    first = authorization(index=1)
    second = authorization(
        index=2,
        decision="REQUIRE_APPROVAL",
        agent="finance-agent",
        action="refund_payment",
        policy_id="refund-limit",
        reason="Large refund requires human review.",
    )
    third = authorization(
        index=3,
        decision="DENY",
        agent="finance-agent",
        action="bank_transfer",
        policy_id="unverified-account",
        reason="Unverified accounts are denied.",
    )

    for item in (first, third):
        store.save_authorization_with_approval(
            authorization=item,
            approval=None,
        )

    store.save_authorization_with_approval(
        authorization=second,
        approval=ApprovalRecord(
            decision_id=second.decision_id,
            status="PENDING",
            requested_at=second.evaluated_at,
        ),
    )

    return store, [first, second, third]


def test_search_combines_exact_policy_and_approval_filters(tmp_path):
    store, records = seeded_store(tmp_path)

    results = store.search_decisions(
        project_id=FIRST_PROJECT_ID,
        filters=DecisionSearchFilters(
            decision="REQUIRE_APPROVAL",
            agent="finance-agent",
            action="refund_payment",
            policy_id="refund-limit",
            has_policy=True,
            approval_status="PENDING",
        ),
    )

    assert results == [records[1]]
    assert store.count_searched_decisions(
        project_id=FIRST_PROJECT_ID,
        filters=DecisionSearchFilters(
            approval_status="PENDING"
        ),
    ) == 1


def test_search_supports_no_policy_no_approval_and_text_query(tmp_path):
    store, records = seeded_store(tmp_path)

    without_policy = store.search_decisions(
        project_id=FIRST_PROJECT_ID,
        filters=DecisionSearchFilters(
            has_policy=False,
            approval_status="NONE",
        ),
    )
    text_match = store.search_decisions(
        project_id=FIRST_PROJECT_ID,
        filters=DecisionSearchFilters(query="HUMAN REVIEW"),
    )

    assert without_policy == [records[0]]
    assert text_match == [records[1]]


def test_search_supports_utc_range_order_and_pagination(tmp_path):
    store, records = seeded_store(tmp_path)
    filters = DecisionSearchFilters(
        evaluated_after=records[0].evaluated_at,
        evaluated_before=records[2].evaluated_at,
        sort="asc",
    )

    page = store.search_decisions(
        project_id=FIRST_PROJECT_ID,
        filters=filters,
        limit=2,
        offset=1,
    )

    assert page == [records[1], records[2]]
    assert store.count_searched_decisions(
        project_id=FIRST_PROJECT_ID,
        filters=filters,
    ) == 3


def test_search_and_export_snapshot_are_isolated_by_project(tmp_path):
    store, first_project_records = seeded_store(tmp_path)
    second_project_record = authorization(
        index=4,
        project_id=SECOND_PROJECT_ID,
        agent="other-project-agent",
    )
    store.save_authorization_with_approval(
        authorization=second_project_record,
        approval=None,
    )

    first_results = store.search_decisions(
        project_id=FIRST_PROJECT_ID,
        filters=DecisionSearchFilters(),
    )
    second_results = store.search_decisions(
        project_id=SECOND_PROJECT_ID,
        filters=DecisionSearchFilters(),
    )
    second_snapshot = store.create_evidence_export_snapshot(
        project_id=SECOND_PROJECT_ID,
        filters=DecisionSearchFilters(),
    )

    assert {
        item.decision_id for item in first_results
    } == {
        item.decision_id for item in first_project_records
    }
    assert second_results == [second_project_record]
    assert second_snapshot.record_count == 1
    assert second_snapshot.chain_record_count == 1


def test_snapshot_excludes_decisions_written_after_it(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()
    first = authorization(index=1)
    second = authorization(index=2)
    filters = DecisionSearchFilters()
    store.save_authorization_with_approval(first, None)

    snapshot = store.create_evidence_export_snapshot(
        project_id=FIRST_PROJECT_ID,
        filters=filters,
    )
    store.save_authorization_with_approval(second, None)

    exported = store.list_evidence_records(
        project_id=FIRST_PROJECT_ID,
        filters=filters,
        max_sequence_number=snapshot.max_sequence_number,
    )
    chain = store.list_evidence_chain(
        project_id=FIRST_PROJECT_ID,
        max_sequence_number=snapshot.max_sequence_number,
    )

    assert [item.decision for item in exported] == [first]
    assert len(chain) == 1
    assert chain[0].record_hash == snapshot.chain_head_hash


def test_prepared_export_keeps_approval_filter_snapshot_stable(
    tmp_path,
):
    store, records = seeded_store(tmp_path)
    filters = DecisionSearchFilters(approval_status="PENDING")
    prepared = prepare_evidence_export(
        project_id=FIRST_PROJECT_ID,
        filters=filters,
        store=store,
    )

    store.resolve_approval(
        decision_id=records[1].decision_id,
        project_id=FIRST_PROJECT_ID,
        status="APPROVED",
        resolved_by="security-admin",
        resolved_at=records[1].evaluated_at + timedelta(minutes=1),
    )
    fresh = prepare_evidence_export(
        project_id=FIRST_PROJECT_ID,
        filters=filters,
        store=store,
    )

    assert [
        item.decision.decision_id for item in prepared.records
    ] == [records[1].decision_id]
    assert prepared.snapshot.record_count == 1
    assert fresh.records == ()
    assert fresh.snapshot.record_count == 0


def test_search_filter_model_rejects_ambiguous_or_naive_ranges():
    with pytest.raises(ValidationError):
        DecisionSearchFilters(
            policy_id="refund-limit",
            has_policy=False,
        )

    with pytest.raises(ValidationError):
        DecisionSearchFilters(
            evaluated_after=datetime(2026, 8, 29, 10, 0),
        )

    with pytest.raises(ValidationError):
        DecisionSearchFilters(
            evaluated_after=BASE_TIME + timedelta(days=1),
            evaluated_before=BASE_TIME,
        )


def test_initialize_creates_decision_search_indexes(tmp_path):
    store = EvidenceStore(tmp_path / "test.db")
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        index_names = {
            row[1]
            for row in connection.execute(
                "PRAGMA index_list(authorization_decisions)"
            ).fetchall()
        }

    assert {
        "idx_decisions_project_time",
        "idx_decisions_project_decision",
        "idx_decisions_project_agent",
        "idx_decisions_project_action",
        "idx_decisions_project_policy",
    } <= index_names

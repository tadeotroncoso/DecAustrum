from typing import Annotated
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    Query,
    Response,
)
from fastapi.responses import StreamingResponse

from app.dependencies import (
    get_authenticated_project,
    get_evidence_store,
    require_admin_access,
)
from app.evidence import (
    iter_csv_export,
    iter_json_export,
    iter_ndjson_export,
)
from app.evidence_models import (
    DecisionSearchFilters,
    EvidenceExportFormat,
)
from app.evidence_store import EvidenceStore
from app.integrity_models import Sha256Digest
from app.project_models import Project
from app.routers.search import DecisionSearchDependency
from app.services.evidence import (
    create_evidence_bundle_archive,
    evidence_response_headers,
    prepare_evidence_export,
)
from app.services.projects import get_project_or_404


router = APIRouter()

ExportFormatQuery = Annotated[
    EvidenceExportFormat,
    Query(alias="format"),
]
ExpectedHeadHashQuery = Annotated[
    Sha256Digest | None,
    Query(
        description=(
            "Externally trusted current or historical chain "
            "checkpoint."
        ),
    ),
]


def _export_response(
    *,
    project_id: UUID,
    filters: DecisionSearchFilters,
    export_format: EvidenceExportFormat,
    expected_head_hash: str | None,
    store: EvidenceStore,
) -> StreamingResponse:
    prepared = prepare_evidence_export(
        project_id=project_id,
        filters=filters,
        store=store,
        expected_head_hash=expected_head_hash,
    )
    snapshot = prepared.snapshot
    records = iter(prepared.records)
    extension = export_format

    if export_format == "json":
        body = iter_json_export(
            snapshot=snapshot,
            criteria=filters,
            records=records,
        )
        media_type = "application/json"
    elif export_format == "ndjson":
        body = iter_ndjson_export(records)
        media_type = "application/x-ndjson"
    else:
        body = iter_csv_export(records)
        media_type = "text/csv"

    headers = evidence_response_headers(snapshot)
    headers["Content-Disposition"] = (
        "attachment; filename="
        f'"regtrace-evidence-{project_id}.{extension}"'
    )

    return StreamingResponse(
        body,
        media_type=media_type,
        headers=headers,
    )


def _bundle_response(
    *,
    project_id: UUID,
    filters: DecisionSearchFilters,
    expected_head_hash: str | None,
    store: EvidenceStore,
) -> Response:
    prepared = prepare_evidence_export(
        project_id=project_id,
        filters=filters,
        store=store,
        expected_head_hash=expected_head_hash,
        include_chain=True,
    )
    bundle, archive = create_evidence_bundle_archive(
        prepared=prepared,
        store=store,
        expected_head_hash=expected_head_hash,
    )
    headers = evidence_response_headers(prepared.snapshot)
    headers.update(
        {
            "Content-Disposition": (
                "attachment; filename="
                f'"regtrace-evidence-bundle-{bundle.manifest.export_id}.zip"'
            ),
            "X-RegTrace-Export-ID": str(
                bundle.manifest.export_id
            ),
            "X-RegTrace-Bundle-SHA256": (
                bundle.manifest.bundle_sha256
            ),
        }
    )

    return Response(
        content=archive,
        media_type="application/zip",
        headers=headers,
    )


@router.get("/v1/evidence/export")
def export_authenticated_project_evidence(
    filters: DecisionSearchDependency,
    export_format: ExportFormatQuery = "json",
    expected_head_hash: ExpectedHeadHashQuery = None,
    project: Project = Depends(get_authenticated_project),
    store: EvidenceStore = Depends(get_evidence_store),
) -> StreamingResponse:
    return _export_response(
        project_id=project.project_id,
        filters=filters,
        export_format=export_format,
        expected_head_hash=expected_head_hash,
        store=store,
    )


@router.get("/v1/evidence/bundle")
def bundle_authenticated_project_evidence(
    filters: DecisionSearchDependency,
    expected_head_hash: ExpectedHeadHashQuery = None,
    project: Project = Depends(get_authenticated_project),
    store: EvidenceStore = Depends(get_evidence_store),
) -> Response:
    return _bundle_response(
        project_id=project.project_id,
        filters=filters,
        expected_head_hash=expected_head_hash,
        store=store,
    )


@router.get(
    "/v1/admin/projects/{project_id}/evidence/export",
    dependencies=[Depends(require_admin_access)],
)
def export_managed_project_evidence(
    project_id: UUID,
    filters: DecisionSearchDependency,
    export_format: ExportFormatQuery = "json",
    expected_head_hash: ExpectedHeadHashQuery = None,
    store: EvidenceStore = Depends(get_evidence_store),
) -> StreamingResponse:
    get_project_or_404(project_id=project_id, store=store)

    return _export_response(
        project_id=project_id,
        filters=filters,
        export_format=export_format,
        expected_head_hash=expected_head_hash,
        store=store,
    )


@router.get(
    "/v1/admin/projects/{project_id}/evidence/bundle",
    dependencies=[Depends(require_admin_access)],
)
def bundle_managed_project_evidence(
    project_id: UUID,
    filters: DecisionSearchDependency,
    expected_head_hash: ExpectedHeadHashQuery = None,
    store: EvidenceStore = Depends(get_evidence_store),
) -> Response:
    get_project_or_404(project_id=project_id, store=store)

    return _bundle_response(
        project_id=project_id,
        filters=filters,
        expected_head_hash=expected_head_hash,
        store=store,
    )


__all__ = ["router"]

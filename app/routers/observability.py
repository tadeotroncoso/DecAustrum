from fastapi import APIRouter, Depends, Response

from app.dependencies import (
    get_metrics_registry,
    require_admin_access,
)
from app.observability import MetricsRegistry

router = APIRouter()


@router.get(
    "/metrics",
    dependencies=[Depends(require_admin_access)],
    include_in_schema=False,
)
def prometheus_metrics(
    metrics: MetricsRegistry = Depends(get_metrics_registry),
) -> Response:
    return Response(
        content=metrics.render_prometheus(),
        headers={
            "Content-Type": (
                "text/plain; version=0.0.4; charset=utf-8"
            )
        },
    )


__all__ = ["router"]

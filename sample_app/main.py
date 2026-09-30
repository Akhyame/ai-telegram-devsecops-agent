"""FastAPI sample application used by the DevSecOps pipeline."""

from collections.abc import Awaitable, Callable
from time import perf_counter

from fastapi import FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from sample_app.config import get_settings
from sample_app.logging_config import configure_application_logger
from sample_app.metrics import (
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
)
from sample_app.monitoring_alert_endpoint import (
    router as monitoring_alert_router,
)
from sample_app.schemas import (
    LivenessResponse,
    ReadinessResponse,
    ServiceInfoResponse,
)
from sample_app.webhook_endpoint import (
    router as webhook_router,
)

settings = get_settings()
logger = configure_application_logger(settings.log_level)
documentation_enabled = settings.environment != "production"

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Secure sample API for CI/CD and DevSecOps validation.",
    docs_url="/docs" if documentation_enabled else None,
    redoc_url=None,
    openapi_url="/openapi.json" if documentation_enabled else None,
)
app.include_router(webhook_router)
app.include_router(monitoring_alert_router)


def _route_template(request: Request) -> str:
    """Return a bounded route label instead of user-controlled URL data."""

    route = request.scope.get("route")
    return getattr(route, "path", "unmatched")


@app.middleware("http")
async def record_http_metrics(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Record request count and duration without high-cardinality labels."""

    started_at = perf_counter()
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        route = _route_template(request)
        duration = perf_counter() - started_at

        HTTP_REQUESTS_TOTAL.labels(
            method=request.method,
            route=route,
            status_code=str(status_code),
        ).inc()

        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=request.method,
            route=route,
        ).observe(duration)

        logger.info(
            "http_request",
            extra={
                "event": "http_request",
                "http_method": request.method,
                "http_route": route,
                "http_status_code": status_code,
                "duration_ms": round(duration * 1000, 3),
            },
        )


@app.get(
    "/health/live",
    response_model=LivenessResponse,
    tags=["Health"],
)
async def liveness() -> LivenessResponse:
    """Confirm that the application process is alive."""

    return LivenessResponse()


@app.get(
    "/health/ready",
    response_model=ReadinessResponse,
    tags=["Health"],
)
async def readiness() -> ReadinessResponse:
    """Confirm that the application is ready to receive traffic."""

    return ReadinessResponse()


@app.get(
    "/api/v1/info",
    response_model=ServiceInfoResponse,
    tags=["Service"],
)
async def service_info() -> ServiceInfoResponse:
    """Return public non-sensitive service metadata."""

    return ServiceInfoResponse(
        name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
    )


@app.get(
    "/metrics",
    include_in_schema=False,
)
async def metrics() -> Response:
    """Expose metrics in the Prometheus text format."""

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )

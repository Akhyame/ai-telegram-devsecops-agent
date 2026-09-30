"""Authenticated GitLab pipeline webhook endpoint."""

import json
from json import JSONDecodeError
from time import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status

from bot.rate_limit import BoundedRateLimiter
from sample_app.webhook_config import (
    ALLOWED_GITLAB_WEBHOOK_EVENTS,
    GITLAB_WEBHOOK_INSTANCE,
    WebhookConfigurationError,
    get_webhook_settings,
)
from sample_app.webhook_events import normalize_pipeline_event, webhook_replay_guard
from sample_app.webhook_notifications import (
    PipelineNotificationConfigurationError,
    notify_pipeline_event,
)
from sample_app.webhook_security import (
    WebhookRequestError,
    read_bounded_webhook_body,
    verify_webhook_request,
)

WEBHOOK_PATH = "/webhooks/gitlab"
INVALID_WEBHOOK_MESSAGE = "Invalid webhook request."
SERVICE_UNAVAILABLE_MESSAGE = "Service unavailable."
RATE_LIMITED_MESSAGE = "Too many requests."
WEBHOOK_RATE_LIMIT_MAX_REQUESTS = 30
WEBHOOK_RATE_LIMIT_WINDOW_SECONDS = 60.0

webhook_rate_limiter = BoundedRateLimiter(
    maximum_requests=WEBHOOK_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=WEBHOOK_RATE_LIMIT_WINDOW_SECONDS,
    maximum_entries=1,
)

router = APIRouter()


def _invalid_request() -> WebhookRequestError:
    return WebhookRequestError("Webhook request is invalid.")


def _required_header(request: Request, name: str) -> str:
    value = request.headers.get(name)

    if value is None:
        raise _invalid_request()

    return value


def _validate_delivery_headers(request: Request) -> tuple[str, str, str]:
    content_type = _required_header(request, "content-type")
    media_type = content_type.split(";", maxsplit=1)[0].strip().lower()

    if media_type != "application/json":
        raise _invalid_request()

    event = _required_header(request, "x-gitlab-event")

    if event not in ALLOWED_GITLAB_WEBHOOK_EVENTS:
        raise _invalid_request()

    instance = _required_header(request, "x-gitlab-instance")

    if instance != GITLAB_WEBHOOK_INSTANCE:
        raise _invalid_request()

    return (
        _required_header(request, "webhook-id"),
        _required_header(request, "webhook-timestamp"),
        _required_header(request, "webhook-signature"),
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise _invalid_request()

        result[key] = value

    return result


def _load_payload(body: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(body, object_pairs_hook=_unique_object)
    except (
        JSONDecodeError,
        UnicodeDecodeError,
        RecursionError,
        WebhookRequestError,
    ) as exc:
        raise _invalid_request() from exc

    if not isinstance(payload, dict):
        raise _invalid_request()

    return payload


@router.post(
    WEBHOOK_PATH,
    include_in_schema=False,
    status_code=status.HTTP_202_ACCEPTED,
)
async def gitlab_webhook(request: Request) -> Response:
    """Accept each authenticated project-scoped pipeline event once."""

    try:
        settings = get_webhook_settings()
    except WebhookConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=SERVICE_UNAVAILABLE_MESSAGE,
        ) from exc

    try:
        message_id, timestamp, signatures = _validate_delivery_headers(request)
        body = await read_bounded_webhook_body(request)
        current_timestamp = int(time())
        verify_webhook_request(
            settings=settings,
            message_id=message_id,
            timestamp=timestamp,
            received_signatures=signatures,
            body=body,
            current_timestamp=current_timestamp,
        )

        if not webhook_rate_limiter.allow("gitlab-webhook"):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=RATE_LIMITED_MESSAGE,
            )
        payload = _load_payload(body)
        event = normalize_pipeline_event(payload, project_id=settings.project_id)

        if not webhook_replay_guard.claim(
            message_id,
            current_timestamp=current_timestamp,
        ):
            return Response(status_code=status.HTTP_202_ACCEPTED)
    except WebhookRequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=INVALID_WEBHOOK_MESSAGE,
        ) from exc

    try:
        await notify_pipeline_event(event)
    except PipelineNotificationConfigurationError as exc:
        webhook_replay_guard.release(message_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=SERVICE_UNAVAILABLE_MESSAGE,
        ) from exc

    return Response(status_code=status.HTTP_202_ACCEPTED)

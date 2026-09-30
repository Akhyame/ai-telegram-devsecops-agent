"""Authenticated internal receiver for normalized Alertmanager events."""

import hmac
import json
from json import JSONDecodeError

from fastapi import APIRouter, HTTPException, Request, Response, status

from bot.config import BotConfigurationError, get_bot_settings
from bot.rate_limit import BoundedRateLimiter
from sample_app.monitoring_alert_config import (
    MAX_MONITORING_ALERT_BODY_BYTES,
    MONITORING_ALERT_RECEIVER_PATH,
    MonitoringAlertConfigurationError,
    get_monitoring_alert_settings,
)
from sample_app.monitoring_alert_events import (
    MonitoringAlertRequestError,
    normalize_monitoring_alert_payload,
)
from sample_app.monitoring_alert_notifications import (
    MonitoringNotificationConfigurationError,
    MonitoringNotificationDeliveryError,
    TelegramMonitoringNotifier,
)

INVALID_MONITORING_ALERT_MESSAGE = "Invalid monitoring alert request."
MONITORING_ALERT_SERVICE_UNAVAILABLE = "Monitoring alert receiver is unavailable."
MONITORING_RATE_LIMITED_MESSAGE = "Too many requests."
MONITORING_RATE_LIMIT_MAX_REQUESTS = 30
MONITORING_RATE_LIMIT_WINDOW_SECONDS = 60.0

monitoring_alert_rate_limiter = BoundedRateLimiter(
    maximum_requests=MONITORING_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=MONITORING_RATE_LIMIT_WINDOW_SECONDS,
    maximum_entries=1,
)

router = APIRouter()


class MonitoringAlertBodyError(ValueError):
    """Raised when the request body violates the receiver contract."""


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=INVALID_MONITORING_ALERT_MESSAGE,
    )


def _invalid_request() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=INVALID_MONITORING_ALERT_MESSAGE,
    )


def _verify_authorization(
    request: Request,
    *,
    expected_token: str,
) -> None:
    authorization = request.headers.get("authorization")

    if not authorization:
        raise _unauthorized()

    scheme, separator, credential = authorization.partition(" ")

    if (
        scheme != "Bearer"
        or not separator
        or not credential
        or credential != credential.strip()
        or " " in credential
    ):
        raise _unauthorized()

    if not hmac.compare_digest(credential, expected_token):
        raise _unauthorized()


def _verify_content_type(request: Request) -> None:
    content_type = request.headers.get("content-type", "")
    media_type = content_type.partition(";")[0].strip().lower()

    if media_type != "application/json":
        raise MonitoringAlertBodyError("Monitoring alert content type is invalid.")


async def read_bounded_monitoring_alert_body(
    request: Request,
) -> bytes:
    """Read at most the configured monitoring payload limit."""

    declared_length = request.headers.get("content-length")

    if declared_length:
        try:
            parsed_length = int(declared_length)
        except ValueError as exc:
            raise MonitoringAlertBodyError("Monitoring alert body length is invalid.") from exc

        if parsed_length < 0 or parsed_length > MAX_MONITORING_ALERT_BODY_BYTES:
            raise MonitoringAlertBodyError("Monitoring alert body is too large.")

    body = bytearray()

    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_MONITORING_ALERT_BODY_BYTES:
            raise MonitoringAlertBodyError("Monitoring alert body is too large.")

        body.extend(chunk)

    return bytes(body)


def _load_payload(body: bytes) -> object:
    try:
        return json.loads(body)
    except (JSONDecodeError, UnicodeDecodeError) as exc:
        raise MonitoringAlertBodyError("Monitoring alert JSON is invalid.") from exc


@router.post(
    MONITORING_ALERT_RECEIVER_PATH,
    include_in_schema=False,
    status_code=status.HTTP_202_ACCEPTED,
)
async def monitoring_alert_receiver(
    request: Request,
) -> Response:
    """Accept authenticated, bounded, allowlisted monitoring evidence."""

    try:
        settings = get_monitoring_alert_settings()
    except MonitoringAlertConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=MONITORING_ALERT_SERVICE_UNAVAILABLE,
        ) from exc

    _verify_authorization(
        request,
        expected_token=settings.receiver_token.get_secret_value(),
    )

    if not monitoring_alert_rate_limiter.allow("monitoring-alert-receiver"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=MONITORING_RATE_LIMITED_MESSAGE,
        )

    try:
        _verify_content_type(request)
        body = await read_bounded_monitoring_alert_body(request)
        payload = _load_payload(body)
        events = normalize_monitoring_alert_payload(payload)
    except (
        MonitoringAlertBodyError,
        MonitoringAlertRequestError,
    ) as exc:
        raise _invalid_request() from exc

    try:
        bot_settings = get_bot_settings()
        notifier = TelegramMonitoringNotifier(bot_settings)

        for event in events:
            await notifier.send(event)
    except (
        BotConfigurationError,
        MonitoringNotificationConfigurationError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=MONITORING_ALERT_SERVICE_UNAVAILABLE,
        ) from exc
    except MonitoringNotificationDeliveryError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Monitoring alert delivery failed.",
        ) from exc

    return Response(status_code=status.HTTP_202_ACCEPTED)

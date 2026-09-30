"""Controlled Telegram delivery for normalized monitoring alerts."""

import json
from json import JSONDecodeError

import httpx

from bot.config import BotSettings
from sample_app.monitoring_alert_events import MonitoringAlertEvent

TELEGRAM_API_ORIGIN = "https://api.telegram.org"
TELEGRAM_REQUEST_TIMEOUT_SECONDS = 5.0
MAX_TELEGRAM_RESPONSE_BYTES = 65_536


class MonitoringNotificationConfigurationError(RuntimeError):
    """Raised when no safe Telegram destination is configured."""


class MonitoringNotificationDeliveryError(RuntimeError):
    """Raised when Telegram does not confirm monitoring delivery."""


def _monitoring_notification_text(
    event: MonitoringAlertEvent,
) -> str:
    """Format only normalized deterministic monitoring fields."""

    return (
        "Monitoring alert.\n"
        f"Status: {event.status.upper()}.\n"
        f"Alert: {event.alert_name}.\n"
        f"Severity: {event.severity}.\n"
        f"Service: {event.service}."
    )


def _delivery_error() -> MonitoringNotificationDeliveryError:
    return MonitoringNotificationDeliveryError("Telegram monitoring notification delivery failed.")


async def _read_response(
    response: httpx.Response,
) -> None:
    body = bytearray()

    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > MAX_TELEGRAM_RESPONSE_BYTES:
            raise _delivery_error()

        body.extend(chunk)

    try:
        payload = json.loads(body)
    except (
        JSONDecodeError,
        UnicodeDecodeError,
        RecursionError,
    ) as exc:
        raise _delivery_error() from exc

    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise _delivery_error()


class TelegramMonitoringNotifier:
    """Send normalized monitoring alerts to configured Telegram admins."""

    def __init__(
        self,
        settings: BotSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.admin_user_ids:
            raise MonitoringNotificationConfigurationError(
                "Telegram monitoring notification configuration is invalid."
            )

        self._settings = settings
        self._transport = transport

    async def send(
        self,
        event: MonitoringAlertEvent,
    ) -> bool:
        """Send one minimized monitoring event to each configured admin."""

        token = self._settings.token.get_secret_value()
        endpoint = f"{TELEGRAM_API_ORIGIN}/bot{token}/sendMessage"

        request_body: dict[str, object] = {
            "text": _monitoring_notification_text(event),
            "link_preview_options": {
                "is_disabled": True,
            },
            "protect_content": True,
        }

        try:
            async with httpx.AsyncClient(
                timeout=TELEGRAM_REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                for chat_id in sorted(self._settings.admin_user_ids):
                    request_body["chat_id"] = chat_id

                    async with client.stream(
                        "POST",
                        endpoint,
                        json=request_body,
                    ) as response:
                        if response.status_code != 200:
                            raise _delivery_error()

                        await _read_response(response)

        except MonitoringNotificationDeliveryError:
            raise
        except httpx.HTTPError as exc:
            raise _delivery_error() from exc

        return True

import asyncio
import base64
import json

import httpx
import pytest

from bot.config import get_bot_settings
from sample_app.monitoring_alert_events import MonitoringAlertEvent
from sample_app.monitoring_alert_notifications import (
    MonitoringNotificationConfigurationError,
    MonitoringNotificationDeliveryError,
    TelegramMonitoringNotifier,
)

_ADMIN_ID = 123456789
_SECOND_ADMIN_ID = 987654321


def _configure_bot(
    monkeypatch: pytest.MonkeyPatch,
    *,
    admin_ids: str = str(_ADMIN_ID),
) -> None:
    encoded = base64.b64encode(b"x" * 32).decode("ascii")

    monkeypatch.setenv(
        "TELEGRAM_BOT_TOKEN",
        "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
    )
    monkeypatch.setenv(
        "TELEGRAM_ALLOWED_USER_IDS",
        admin_ids,
    )
    monkeypatch.setenv(
        "TELEGRAM_ADMIN_USER_IDS",
        admin_ids,
    )

    # Existing settings may require these unrelated values.
    monkeypatch.setenv(
        "GITLAB_WEBHOOK_SIGNING_TOKEN",
        f"whsec_{encoded}",
    )

    get_bot_settings.cache_clear()


def _event(
    *,
    name: str = "SampleAppUnavailable",
    status: str = "firing",
    severity: str = "critical",
) -> MonitoringAlertEvent:
    return MonitoringAlertEvent(
        alert_name=name,
        status=status,
        severity=severity,
        service="sample-app",
    )


def test_minimized_monitoring_message_is_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_bot(monkeypatch)

    captured: list[dict[str, object]] = []

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        captured.append(json.loads(request.content))

        return httpx.Response(
            200,
            json={"ok": True},
        )

    notifier = TelegramMonitoringNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(notifier.send(_event())) is True

    assert len(captured) == 1

    body = captured[0]

    assert body["chat_id"] == _ADMIN_ID
    assert body["protect_content"] is True
    assert body["link_preview_options"] == {
        "is_disabled": True,
    }

    text = str(body["text"])

    assert "Status: FIRING." in text
    assert "Alert: SampleAppUnavailable." in text
    assert "Severity: critical." in text
    assert "Service: sample-app." in text


def test_resolved_notification_is_minimized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_bot(monkeypatch)

    captured: list[dict[str, object]] = []

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        captured.append(json.loads(request.content))

        return httpx.Response(
            200,
            json={"ok": True},
        )

    notifier = TelegramMonitoringNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    asyncio.run(
        notifier.send(
            _event(
                status="resolved",
            )
        )
    )

    assert "Status: RESOLVED." in str(captured[0]["text"])


def test_each_admin_receives_one_notification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_bot(
        monkeypatch,
        admin_ids=f"{_ADMIN_ID},{_SECOND_ADMIN_ID}",
    )

    captured: list[int] = []

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        payload = json.loads(request.content)
        captured.append(payload["chat_id"])

        return httpx.Response(
            200,
            json={"ok": True},
        )

    notifier = TelegramMonitoringNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    asyncio.run(notifier.send(_event()))

    assert captured == [
        _ADMIN_ID,
        _SECOND_ADMIN_ID,
    ]


def test_raw_alertmanager_fields_cannot_be_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_bot(monkeypatch)

    captured: list[dict[str, object]] = []

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        captured.append(json.loads(request.content))

        return httpx.Response(
            200,
            json={"ok": True},
        )

    notifier = TelegramMonitoringNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    asyncio.run(notifier.send(_event()))

    serialized = json.dumps(captured)

    assert "annotations" not in serialized
    assert "generatorURL" not in serialized
    assert "fingerprint" not in serialized
    assert "api:8000" not in serialized
    assert "alertmanager:9093" not in serialized


def test_missing_admin_destination_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.chdir(tmp_path)

    monkeypatch.setenv(
        "TELEGRAM_BOT_TOKEN",
        "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
    )
    monkeypatch.delenv(
        "TELEGRAM_ALLOWED_USER_IDS",
        raising=False,
    )
    monkeypatch.delenv(
        "TELEGRAM_OPERATOR_USER_IDS",
        raising=False,
    )
    monkeypatch.delenv(
        "TELEGRAM_ADMIN_USER_IDS",
        raising=False,
    )

    get_bot_settings.cache_clear()

    with pytest.raises(
        MonitoringNotificationConfigurationError,
    ):
        TelegramMonitoringNotifier(get_bot_settings())


@pytest.mark.parametrize(
    ("status_code", "payload"),
    [
        (500, {"ok": False}),
        (200, {"ok": False}),
    ],
)
def test_telegram_failure_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    payload: dict[str, object],
) -> None:
    _configure_bot(monkeypatch)

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code,
            json=payload,
        )

    notifier = TelegramMonitoringNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(
        MonitoringNotificationDeliveryError,
    ):
        asyncio.run(notifier.send(_event()))


def test_invalid_telegram_json_response_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_bot(monkeypatch)

    async def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{invalid",
        )

    notifier = TelegramMonitoringNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(
        MonitoringNotificationDeliveryError,
    ):
        asyncio.run(notifier.send(_event()))

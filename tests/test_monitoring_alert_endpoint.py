import base64

import pytest
from fastapi.testclient import TestClient

import sample_app.monitoring_alert_endpoint as monitoring_alert_endpoint
from sample_app.main import app
from sample_app.monitoring_alert_config import (
    MAX_MONITORING_ALERT_BODY_BYTES,
    MONITORING_ALERT_RECEIVER_PATH,
    get_monitoring_alert_settings,
)


def _valid_token() -> str:
    encoded = base64.b64encode(b"x" * 32).decode("ascii")
    return f"amsec_{encoded}"


def _payload(
    *,
    name: str = "SampleAppUnavailable",
    alert_status: str = "firing",
    group_status: str = "firing",
    severity: str = "critical",
) -> dict[str, object]:
    return {
        "version": "4",
        "receiver": "monitoring-webhook",
        "status": group_status,
        "truncatedAlerts": 0,
        "alerts": [
            {
                "status": alert_status,
                "labels": {
                    "alertname": name,
                    "severity": severity,
                    "service": "sample-app",
                    "instance": "api:8000",
                },
                "annotations": {
                    "summary": "not forwarded",
                },
            }
        ],
    }


class _NoNetworkMonitoringNotifier:
    """Test double that prevents real Telegram network access."""

    def __init__(self, settings: object) -> None:
        self._settings = settings

    async def send(self, event: object) -> bool:
        return True


@pytest.fixture(autouse=True)
def _block_real_telegram(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        monitoring_alert_endpoint,
        "get_bot_settings",
        lambda: object(),
    )
    monkeypatch.setattr(
        monitoring_alert_endpoint,
        "TelegramMonitoringNotifier",
        _NoNetworkMonitoringNotifier,
    )


@pytest.fixture(autouse=True)
def _clear_settings_cache() -> None:
    get_monitoring_alert_settings.cache_clear()
    monitoring_alert_endpoint.monitoring_alert_rate_limiter.clear()
    yield
    monitoring_alert_endpoint.monitoring_alert_rate_limiter.clear()
    get_monitoring_alert_settings.cache_clear()


@pytest.fixture
def client(
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    monkeypatch.setenv(
        "ALERTMANAGER_RECEIVER_TOKEN",
        _valid_token(),
    )
    return TestClient(app)


def _headers(
    token: str | None = None,
) -> dict[str, str]:
    value = _valid_token() if token is None else token

    return {
        "Authorization": f"Bearer {value}",
        "Content-Type": "application/json",
    }


def test_valid_firing_alert_is_accepted(
    client: TestClient,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(),
    )

    assert response.status_code == 202
    assert response.content == b""


def test_valid_resolved_alert_is_accepted(
    client: TestClient,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(
            alert_status="resolved",
            group_status="resolved",
        ),
    )

    assert response.status_code == 202


def test_missing_authorization_is_rejected(
    client: TestClient,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers={"Content-Type": "application/json"},
        json=_payload(),
    )

    assert response.status_code == 401


@pytest.mark.parametrize(
    "authorization",
    [
        "Bearer invalid",
        "Basic invalid",
        "bearer invalid",
        "Bearer invalid extra",
    ],
)
def test_invalid_authorization_is_rejected(
    client: TestClient,
    authorization: str,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers={
            "Authorization": authorization,
            "Content-Type": "application/json",
        },
        json=_payload(),
    )

    assert response.status_code == 401
    assert _valid_token() not in response.text


def test_missing_receiver_configuration_returns_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "ALERTMANAGER_RECEIVER_TOKEN",
        raising=False,
    )
    get_monitoring_alert_settings.cache_clear()

    client = TestClient(app)

    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers={
            "Authorization": "Bearer unavailable",
            "Content-Type": "application/json",
        },
        json=_payload(),
    )

    assert response.status_code == 503


@pytest.mark.parametrize(
    "content_type",
    [
        "text/plain",
        "application/xml",
    ],
)
def test_non_json_content_type_is_rejected(
    client: TestClient,
    content_type: str,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers={
            "Authorization": f"Bearer {_valid_token()}",
            "Content-Type": content_type,
        },
        content=b"{}",
    )

    assert response.status_code == 400


def test_invalid_json_is_rejected(
    client: TestClient,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        content=b"{invalid",
    )

    assert response.status_code == 400


def test_unknown_alert_is_rejected(
    client: TestClient,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(
            name="UnknownAlert",
            severity="warning",
        ),
    )

    assert response.status_code == 400


def test_oversized_body_is_rejected(
    client: TestClient,
) -> None:
    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        content=b"x" * (MAX_MONITORING_ALERT_BODY_BYTES + 1),
    )

    assert response.status_code == 400


def test_receiver_is_hidden_from_openapi(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert MONITORING_ALERT_RECEIVER_PATH not in response.json()["paths"]


def test_normalized_event_reaches_notifier(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    delivered: list[object] = []

    class RecordingNotifier:
        def __init__(self, settings: object) -> None:
            self._settings = settings

        async def send(self, event: object) -> bool:
            delivered.append(event)
            return True

    monkeypatch.setattr(
        monitoring_alert_endpoint,
        "TelegramMonitoringNotifier",
        RecordingNotifier,
    )

    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(),
    )

    assert response.status_code == 202
    assert len(delivered) == 1

    event = delivered[0]

    assert event.alert_name == "SampleAppUnavailable"
    assert event.status == "firing"
    assert event.severity == "critical"
    assert event.service == "sample-app"
    assert not hasattr(event, "annotations")
    assert not hasattr(event, "instance")


def test_invalid_alert_never_reaches_notification_layer(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_bot_settings() -> object:
        raise AssertionError(
            "Notification configuration must not load for an invalid alert payload."
        )

    monkeypatch.setattr(
        monitoring_alert_endpoint,
        "get_bot_settings",
        unexpected_bot_settings,
    )

    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(
            name="UnknownAlert",
            severity="warning",
        ),
    )

    assert response.status_code == 400


def test_notification_configuration_failure_returns_503(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ConfigurationFailureNotifier:
        def __init__(self, settings: object) -> None:
            raise monitoring_alert_endpoint.MonitoringNotificationConfigurationError(
                "test configuration failure"
            )

    monkeypatch.setattr(
        monitoring_alert_endpoint,
        "TelegramMonitoringNotifier",
        ConfigurationFailureNotifier,
    )

    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Monitoring alert receiver is unavailable."}


def test_notification_delivery_failure_returns_502(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeliveryFailureNotifier:
        def __init__(self, settings: object) -> None:
            self._settings = settings

        async def send(self, event: object) -> bool:
            raise monitoring_alert_endpoint.MonitoringNotificationDeliveryError(
                "test delivery failure"
            )

    monkeypatch.setattr(
        monitoring_alert_endpoint,
        "TelegramMonitoringNotifier",
        DeliveryFailureNotifier,
    )

    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(),
    )

    assert response.status_code == 502
    assert response.json() == {"detail": "Monitoring alert delivery failed."}


def test_authenticated_monitoring_receiver_is_rate_limited(
    client: TestClient,
) -> None:
    for _ in range(monitoring_alert_endpoint.MONITORING_RATE_LIMIT_MAX_REQUESTS):
        response = client.post(
            MONITORING_ALERT_RECEIVER_PATH,
            headers=_headers(),
            json=_payload(),
        )

        assert response.status_code == 202

    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(),
    )

    assert response.status_code == 429
    assert response.json() == {
        "detail": monitoring_alert_endpoint.MONITORING_RATE_LIMITED_MESSAGE,
    }


def test_invalid_monitoring_authentication_does_not_consume_rate_limit(
    client: TestClient,
) -> None:
    for _ in range(monitoring_alert_endpoint.MONITORING_RATE_LIMIT_MAX_REQUESTS + 2):
        response = client.post(
            MONITORING_ALERT_RECEIVER_PATH,
            headers=_headers("invalid"),
            json=_payload(),
        )

        assert response.status_code == 401

    response = client.post(
        MONITORING_ALERT_RECEIVER_PATH,
        headers=_headers(),
        json=_payload(),
    )

    assert response.status_code == 202

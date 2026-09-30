import base64

import pytest
from pydantic import ValidationError

from sample_app.monitoring_alert_config import (
    ALLOWED_MONITORING_ALERT_NAMES,
    ALLOWED_MONITORING_ALERT_STATUSES,
    MAX_MONITORING_ALERT_BODY_BYTES,
    MAX_MONITORING_ALERTS_PER_NOTIFICATION,
    MONITORING_ALERT_RECEIVER_PATH,
    MonitoringAlertConfigurationError,
    MonitoringAlertSettings,
    get_monitoring_alert_settings,
)


def _valid_token() -> str:
    encoded = base64.b64encode(b"x" * 32).decode("ascii")
    return f"amsec_{encoded}"


def test_monitoring_alert_contract_is_bounded() -> None:
    assert MONITORING_ALERT_RECEIVER_PATH == ("/internal/monitoring/alerts")

    assert MAX_MONITORING_ALERT_BODY_BYTES == 65_536
    assert MAX_MONITORING_ALERTS_PER_NOTIFICATION == 10

    assert ALLOWED_MONITORING_ALERT_NAMES == {
        "SampleAppUnavailable",
        "SampleAppHighServerErrors",
        "SampleAppHighLatency",
        "RealFastAPIUnavailable",
        "RealFastAPIHighServerErrors",
        "RealFastAPIHighLatency",
    }

    assert ALLOWED_MONITORING_ALERT_STATUSES == {
        "firing",
        "resolved",
    }


def test_receiver_token_accepts_canonical_32_byte_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ALERTMANAGER_RECEIVER_TOKEN",
        _valid_token(),
    )

    settings = MonitoringAlertSettings()

    assert settings.receiver_token.get_secret_value() == _valid_token()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "invalid",
        "amsec_invalid",
        "amsec_YQ==",
        " amsec_" + base64.b64encode(b"x" * 32).decode("ascii"),
        "amsec_" + base64.b64encode(b"x" * 31).decode("ascii"),
        "amsec_" + base64.b64encode(b"x" * 33).decode("ascii"),
    ],
)
def test_receiver_token_rejects_invalid_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv(
        "ALERTMANAGER_RECEIVER_TOKEN",
        value,
    )

    with pytest.raises(
        ValidationError,
        match="Alertmanager receiver token is invalid",
    ):
        MonitoringAlertSettings()


def test_receiver_secret_is_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "ALERTMANAGER_RECEIVER_TOKEN",
        _valid_token(),
    )

    settings = MonitoringAlertSettings()

    assert _valid_token() not in repr(settings)
    assert _valid_token() not in str(settings.receiver_token)


def test_cached_settings_are_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get_monitoring_alert_settings.cache_clear()

    monkeypatch.setenv(
        "ALERTMANAGER_RECEIVER_TOKEN",
        _valid_token(),
    )

    first = get_monitoring_alert_settings()
    second = get_monitoring_alert_settings()

    assert first is second

    get_monitoring_alert_settings.cache_clear()


def test_controlled_failure_when_receiver_secret_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get_monitoring_alert_settings.cache_clear()

    monkeypatch.delenv(
        "ALERTMANAGER_RECEIVER_TOKEN",
        raising=False,
    )

    with pytest.raises(
        MonitoringAlertConfigurationError,
        match="Monitoring alert receiver configuration is invalid",
    ):
        get_monitoring_alert_settings()

    get_monitoring_alert_settings.cache_clear()

from pathlib import Path

ALERTMANAGER_CONFIG = Path("monitoring/alertmanager/alertmanager.yml").read_text(encoding="utf-8")

PROMETHEUS_CONFIG = Path("monitoring/prometheus/prometheus.yml").read_text(encoding="utf-8")


def test_alertmanager_route_uses_bounded_grouping_contract() -> None:
    assert "receiver: monitoring-webhook" in ALERTMANAGER_CONFIG
    assert "- alertname" in ALERTMANAGER_CONFIG
    assert "- severity" in ALERTMANAGER_CONFIG
    assert "- service" in ALERTMANAGER_CONFIG
    assert "group_wait: 30s" in ALERTMANAGER_CONFIG
    assert "group_interval: 5m" in ALERTMANAGER_CONFIG
    assert "repeat_interval: 4h" in ALERTMANAGER_CONFIG


def test_monitoring_webhook_uses_internal_authenticated_receiver() -> None:
    lowered = ALERTMANAGER_CONFIG.lower()

    assert "webhook_configs:" in ALERTMANAGER_CONFIG
    assert "url: http://api:8000/internal/monitoring/alerts" in ALERTMANAGER_CONFIG
    assert "send_resolved: true" in ALERTMANAGER_CONFIG
    assert "max_alerts: 10" in ALERTMANAGER_CONFIG
    assert "timeout: 5s" in ALERTMANAGER_CONFIG

    assert "authorization:" in ALERTMANAGER_CONFIG
    assert "type: Bearer" in ALERTMANAGER_CONFIG
    assert "credentials_file: /etc/alertmanager/receiver-token" in ALERTMANAGER_CONFIG

    assert "telegram_configs:" not in lowered
    assert "bot_token" not in lowered


def test_alertmanager_contains_no_inline_delivery_secret() -> None:
    lowered = ALERTMANAGER_CONFIG.lower()

    assert "credentials:" not in lowered
    assert "password:" not in lowered
    assert "bot_token:" not in lowered
    assert "token:" not in lowered

    assert "amsec_" not in ALERTMANAGER_CONFIG
    assert "TELEGRAM_BOT_TOKEN" not in ALERTMANAGER_CONFIG
    assert "ALERTMANAGER_RECEIVER_TOKEN" not in ALERTMANAGER_CONFIG


def test_prometheus_routes_alerts_to_internal_alertmanager_target() -> None:
    assert "alerting:" in PROMETHEUS_CONFIG
    assert "alertmanagers:" in PROMETHEUS_CONFIG
    assert "alertmanager:9093" in PROMETHEUS_CONFIG

    assert "127.0.0.1:9093" not in PROMETHEUS_CONFIG
    assert "localhost:9093" not in PROMETHEUS_CONFIG
    assert "http://" not in PROMETHEUS_CONFIG
    assert "https://" not in PROMETHEUS_CONFIG


def test_alertmanager_webhook_is_internal_only() -> None:
    lowered = ALERTMANAGER_CONFIG.lower()

    assert "http://api:8000/internal/monitoring/alerts" in lowered

    assert "localhost" not in lowered
    assert "127.0.0.1" not in ALERTMANAGER_CONFIG
    assert "0.0.0.0" not in ALERTMANAGER_CONFIG  # noqa: S104 - assertion rejects public bind address
    assert "https://" not in lowered

    assert "telegram.org" not in lowered
    assert "gitlab.com" not in lowered
    assert "github.com" not in lowered


def test_alertmanager_configuration_contains_no_public_listener() -> None:
    assert "9093:" not in ALERTMANAGER_CONFIG

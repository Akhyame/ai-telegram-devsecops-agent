from pathlib import Path

PROMETHEUS_CONFIG_PATH = Path("monitoring/prometheus/prometheus.yml")
PROMETHEUS_CONFIG = PROMETHEUS_CONFIG_PATH.read_text(encoding="utf-8")


def test_prometheus_loads_alert_rules_from_internal_config_volume() -> None:
    assert "rule_files:" in PROMETHEUS_CONFIG
    assert "- /etc/prometheus/alerts.yml" in PROMETHEUS_CONFIG


def test_prometheus_keeps_internal_sample_app_scrape_target() -> None:
    assert "job_name: sample-app" in PROMETHEUS_CONFIG
    assert "api:8000" in PROMETHEUS_CONFIG
    assert "127.0.0.1:18000" not in PROMETHEUS_CONFIG
    assert "localhost:18000" not in PROMETHEUS_CONFIG


def test_prometheus_retains_bounded_evaluation_interval() -> None:
    assert "evaluation_interval: 15s" in PROMETHEUS_CONFIG


def test_prometheus_scrapes_real_fastapi_staging() -> None:
    assert "job_name: real-fastapi-staging" in PROMETHEUS_CONFIG
    assert "backend:8000" in PROMETHEUS_CONFIG

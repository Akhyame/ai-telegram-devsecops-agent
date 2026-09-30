import re
from pathlib import Path

RULES_PATH = Path("monitoring/prometheus/alerts.yml")
RULES = RULES_PATH.read_text(encoding="utf-8")


def _alert_block(name: str) -> str:
    match = re.search(
        rf"(?ms)^\s*- alert: {re.escape(name)}\s*$"
        rf"(?P<body>.*?)(?=^\s*- alert: |\Z)",
        RULES,
    )
    assert match is not None, f"Alert {name} not found"
    return match.group("body")


def test_expected_alert_set_is_bounded() -> None:
    expected = {
        "SampleAppUnavailable",
        "SampleAppHighServerErrors",
        "SampleAppHighLatency",
        "RealFastAPIUnavailable",
        "RealFastAPIHighServerErrors",
        "RealFastAPIHighLatency",
    }

    actual = set(re.findall(r"(?m)^\s*- alert:\s+([A-Za-z0-9_-]+)\s*$", RULES))

    assert actual == expected


def test_unavailable_rule_uses_prometheus_up_and_sustained_duration() -> None:
    block = _alert_block("SampleAppUnavailable")

    assert 'up{job="sample-app"} == 0' in block
    assert "for: 2m" in block
    assert "severity: critical" in block


def test_server_error_rule_uses_bounded_http_metric() -> None:
    block = _alert_block("SampleAppHighServerErrors")

    assert "sample_app_http_requests_total" in block
    assert 'status_code=~"5.."' in block
    assert "> 0.05" in block
    assert "for: 5m" in block
    assert "severity: warning" in block


def test_latency_rule_uses_histogram_p95() -> None:
    block = _alert_block("SampleAppHighLatency")

    assert "histogram_quantile(" in block
    assert "0.95" in block
    assert "sample_app_http_request_duration_seconds_bucket" in block
    assert "sample_app_http_request_duration_seconds_count" in block
    assert "> 1" in block
    assert "for: 10m" in block
    assert "severity: warning" in block


def test_alert_metadata_is_static_and_secret_free() -> None:
    lowered = RULES.lower()

    assert "{{" not in RULES
    assert "$labels" not in RULES
    assert "$value" not in RULES

    forbidden = (
        "telegram_bot_token",
        "gitlab_api_token",
        "private-token",
        "authorization:",
        "password:",
        "secret:",
    )

    for value in forbidden:
        assert value not in lowered


def test_alert_labels_do_not_include_request_controlled_dimensions() -> None:
    for alert in (
        "SampleAppUnavailable",
        "SampleAppHighServerErrors",
        "SampleAppHighLatency",
        "RealFastAPIUnavailable",
        "RealFastAPIHighServerErrors",
        "RealFastAPIHighLatency",
    ):
        block = _alert_block(alert)

        labels = block.split("labels:", 1)[1].split("annotations:", 1)[0]

        assert "route:" not in labels
        assert "method:" not in labels
        assert "status_code:" not in labels
        assert "url:" not in labels
        assert "path:" not in labels


def test_real_fastapi_unavailable_rule() -> None:
    block = _alert_block("RealFastAPIUnavailable")

    assert 'up{job="real-fastapi-staging"} == 0' in block
    assert "for: 2m" in block
    assert "severity: critical" in block
    assert "service: real-fastapi-staging" in block


def test_real_fastapi_server_error_rule() -> None:
    block = _alert_block("RealFastAPIHighServerErrors")

    assert "real_fastapi_http_requests_total" in block
    assert 'status_code=~"5.."' in block
    assert "> 0.05" in block
    assert "for: 5m" in block
    assert "severity: warning" in block


def test_real_fastapi_latency_rule() -> None:
    block = _alert_block("RealFastAPIHighLatency")

    assert "histogram_quantile(" in block
    assert "0.95" in block
    assert "real_fastapi_http_request_duration_seconds_bucket" in block
    assert "real_fastapi_http_request_duration_seconds_count" in block
    assert "> 1" in block
    assert "for: 10m" in block
    assert "severity: warning" in block

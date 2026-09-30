"""Offline contracts for isolated Prometheus deployment."""

from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_MONITORING_RELEASE = _REPOSITORY_ROOT / "deployment" / "monitoring.sh"


def _release_text() -> str:
    return _MONITORING_RELEASE.read_text(encoding="utf-8")


def test_monitoring_release_inputs_fail_closed() -> None:
    release = _release_text()

    assert "set -eu" in release
    assert "DEPLOYMENT_ENVIRONMENT is required" in release
    assert "DEPLOYMENT_COMMIT_SHA is required" in release
    assert "Prometheus configuration exceeds size limit." in release
    assert "Prometheus alert rules are unavailable." in release
    assert "Prometheus alert rules size is invalid." in release
    assert "Prometheus alert rules exceed size limit." in release
    assert 'case "${DEPLOYMENT_ENVIRONMENT}:${DEPLOYMENT_COMPOSE_OVERRIDE}"' in release


def test_monitoring_uses_remote_safe_config_volume() -> None:
    release = _release_text()

    assert "--profile monitoring" in release
    assert "docker cp" in release
    assert '"$PROMETHEUS_CONFIG_PATH"' in release
    assert '"$PROMETHEUS_RULES_PATH"' in release
    assert '"${HELPER_NAME}:/config/prometheus.yml"' in release
    assert '"${HELPER_NAME}:/config/alerts.yml"' in release
    assert 'eq .Destination "/etc/prometheus"' in release
    assert '--volume "${config_volume}:/config"' in release
    assert "--entrypoint /bin/promtool" in release
    assert "check rules /etc/prometheus/alerts.yml" in release
    assert "check config /etc/prometheus/prometheus.yml" in release


def test_monitoring_never_rolls_back_core_application() -> None:
    release = _release_text()

    assert "CORE_APPLICATION_ROLLBACK_ATTEMPTED=false" in release
    assert "ROLLBACK_RESULT=" not in release
    assert "deployment_failed_rolled_back" not in release
    assert "compose_command down" not in release
    assert "deploy_sha" not in release


def test_monitoring_runtime_is_bounded_and_internal_only() -> None:
    release = _release_text()

    assert "PROMETHEUS_READINESS_ATTEMPT=" in release
    assert "PROMETHEUS_SCRAPE_ATTEMPT=" in release
    assert "docker port" in release
    assert "MONITORING_NETWORK_INTERNAL=true" in release
    assert 'network_internal" != "true"' in release
    assert "up%7Bjob%3D%22sample-app%22%7D" in release


def test_monitoring_result_is_sanitized() -> None:
    release = _release_text()

    assert '"status"' in release
    assert '"environment"' in release
    assert '"target_commit_sha"' in release

    for forbidden in (
        "CI_REGISTRY_PASSWORD",
        "DEPLOYMENT_SSH_PRIVATE_KEY",
        "GITLAB_API_TOKEN",
        "TELEGRAM_BOT_TOKEN",
    ):
        assert forbidden not in release

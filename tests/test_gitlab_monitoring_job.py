"""Offline CI contracts for isolated staging monitoring deployment."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".gitlab-ci.yml"


def _ci_text() -> str:
    return _CI.read_text(encoding="utf-8")


def _monitoring_job() -> str:
    ci = _ci_text()
    start = ci.index("deploy_staging_monitoring:")
    end = ci.index("deploy_production:", start)
    return ci[start:end]


def test_monitoring_has_dedicated_post_deploy_stage() -> None:
    ci = _ci_text()

    assert (
        """  - deployment_validate
  - deploy
  - monitoring_deploy
"""
        in ci
    )


def test_monitoring_runs_only_after_successful_staging_core_deploy() -> None:
    job = _monitoring_job()

    assert "stage: monitoring_deploy" in job
    assert "- job: validate_staging_deployment" in job
    assert "artifacts: true" in job
    assert "- job: deploy_staging" in job
    assert "artifacts: false" in job
    assert "sh deployment/monitoring.sh" in job


def test_monitoring_is_staging_only_and_serialized() -> None:
    job = _monitoring_job()

    assert "DEPLOYMENT_COMPOSE_OVERRIDE: deployment/compose.staging.yml" in job
    assert 'DEPLOYMENT_API_ENV_FILE: "$STAGING_API_ENV_FILE"' in job
    assert 'DEPLOYMENT_BOT_ENV_FILE: "$STAGING_BOT_ENV_FILE"' in job
    assert "resource_group: staging" in job
    assert 'deployment_environment ]]" == "staging"' in job
    assert "production" not in job


def test_monitoring_uses_verify_environment_without_creating_deployment() -> None:
    job = _monitoring_job()

    assert (
        """  environment:
    name: staging
    action: verify"""
        in job
    )
    assert "action: start" not in job
    assert "deployment_tier:" not in job


def test_monitoring_preserves_sanitized_result_artifact() -> None:
    job = _monitoring_job()

    assert "when: always" in job
    assert "access: maintainer" in job
    assert "- monitoring-result.json" in job

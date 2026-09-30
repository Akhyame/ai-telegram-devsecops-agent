"""Offline contract tests for protected GitLab deployment jobs."""

import re
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_CI_PATH = _REPOSITORY_ROOT / ".gitlab-ci.yml"
_CI_TEXT = _CI_PATH.read_text(encoding="utf-8")


def test_deployment_input_is_closed_by_default() -> None:
    assert "    deployment_environment:\n" in _CI_TEXT
    assert "      default: none\n" in _CI_TEXT
    assert "        - none\n" in _CI_TEXT
    assert "        - staging\n" in _CI_TEXT
    assert "        - production\n" in _CI_TEXT


def test_deployment_stages_are_after_security_gate() -> None:
    expected = "  - security_gate\n  - deployment_validate\n  - deploy\n"

    assert expected in _CI_TEXT


def test_expected_deployment_jobs_exist_once() -> None:
    for job_name in (
        ".deployment_validation",
        "validate_staging_deployment",
        "validate_production_deployment",
        ".deployment_compose",
        "deploy_staging",
        "deploy_production",
    ):
        pattern = rf"(?m)^{re.escape(job_name)}:$"
        assert len(re.findall(pattern, _CI_TEXT)) == 1


def test_validation_consumes_security_gate_artifact() -> None:
    validation_boundary = _CI_TEXT[
        _CI_TEXT.index(".deployment_validation:") : _CI_TEXT.index("validate_staging_deployment:")
    ]

    assert "stage: deployment_validate" in validation_boundary
    assert "- job: security_gate" in validation_boundary
    assert "artifacts: true" in validation_boundary
    assert "python -m deployment.ci_gate" in validation_boundary
    assert "dotenv: deployment.env" in validation_boundary


def test_deployment_rules_require_trusted_pipeline_context() -> None:
    deployment_jobs = _CI_TEXT[_CI_TEXT.index(".deployment_validation:") :]

    required_conditions = (
        '"$[[ inputs.pipeline_profile ]]" == "full"',
        '$CI_PIPELINE_SOURCE == "api"',
        "$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH",
        '$CI_COMMIT_REF_PROTECTED == "true"',
    )

    for condition in required_conditions:
        assert deployment_jobs.count(condition) == 5

    assert deployment_jobs.count('"$[[ inputs.deployment_environment ]]" == "staging"') == 3
    assert deployment_jobs.count('"$[[ inputs.deployment_environment ]]" == "production"') == 2


def test_deployment_uses_immutable_docker_cli_image() -> None:
    pattern = (
        r'name: "(?:docker\.io/library/)?'
        r'docker@sha256:[0-9a-f]{64}"'
    )

    assert re.search(pattern, _CI_TEXT)
    assert 'name: "docker:29-cli"' not in _CI_TEXT


def test_deployment_uses_remote_docker_over_strict_ssh() -> None:
    required_text = (
        'DOCKER_HOST="ssh://deployment-target"',
        "StrictHostKeyChecking yes",
        "BatchMode yes",
        "IdentitiesOnly yes",
        "DEPLOYMENT_SSH_PRIVATE_KEY",
        "DEPLOYMENT_SSH_KNOWN_HOSTS",
    )

    for value in required_text:
        assert value in _CI_TEXT

    assert "/var/run/docker.sock" not in _CI_TEXT
    assert "privileged: true" not in _CI_TEXT
    assert "apk add" not in _CI_TEXT


def test_deployments_are_serialized_per_environment() -> None:
    assert "resource_group: staging" in _CI_TEXT
    assert "resource_group: production" in _CI_TEXT
    assert "name: staging" in _CI_TEXT
    assert "name: production" in _CI_TEXT
    assert "deployment_tier: staging" in _CI_TEXT
    assert "deployment_tier: production" in _CI_TEXT


def test_deployments_use_matching_validation_artifacts() -> None:
    staging_job = _CI_TEXT[_CI_TEXT.index("deploy_staging:") : _CI_TEXT.index("deploy_production:")]
    production_job = _CI_TEXT[_CI_TEXT.index("deploy_production:") :]

    assert "- job: validate_staging_deployment" in staging_job
    assert "artifacts: true" in staging_job
    assert "- job: validate_production_deployment" in production_job
    assert "artifacts: true" in production_job


def test_environment_secrets_remain_file_variable_references() -> None:
    expected_variables = (
        "$STAGING_API_ENV_FILE",
        "$STAGING_BOT_ENV_FILE",
        "$PRODUCTION_API_ENV_FILE",
        "$PRODUCTION_BOT_ENV_FILE",
    )

    for variable in expected_variables:
        assert variable in _CI_TEXT

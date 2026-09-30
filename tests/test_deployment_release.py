"""Offline contracts for deployment health verification and rollback."""

from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_RELEASE_PATH = _REPOSITORY_ROOT / "deployment" / "release.sh"
_CI_PATH = _REPOSITORY_ROOT / ".gitlab-ci.yml"


def _release_text() -> str:
    return _RELEASE_PATH.read_text(encoding="utf-8")


def _deployment_template() -> str:
    ci_text = _CI_PATH.read_text(encoding="utf-8")
    start = ci_text.index(".deployment_compose:")
    end = ci_text.index("deploy_staging:")

    return ci_text[start:end]


def test_release_inputs_fail_closed() -> None:
    release_text = _release_text()

    assert "set -eu" in release_text
    assert "DEPLOYMENT_ENVIRONMENT is required" in release_text
    assert "DEPLOYMENT_COMMIT_SHA is required" in release_text
    assert "^[0-9a-f]{40}$" in release_text
    assert 'case "${DEPLOYMENT_ENVIRONMENT}:${DEPLOYMENT_COMPOSE_OVERRIDE}"' in release_text


def test_previous_release_requires_exact_healthy_service_pair() -> None:
    release_text = _release_text()

    assert "docker ps -aq" in release_text
    assert "com.docker.compose.project=${PROJECT_NAME}" in release_text
    assert "com.docker.compose.service=${service_name}" in release_text
    assert '"$api_count" != "1"' in release_text
    assert '"$bot_count" != "1"' in release_text
    assert '"$api_health" != "healthy"' in release_text
    assert '"$bot_health" != "healthy"' in release_text
    assert '"$api_image" != "$bot_image"' in release_text


def test_candidate_release_is_pulled_and_waited_for() -> None:
    release_text = _release_text()

    assert "compose_command pull" in release_text
    assert "compose_command up" in release_text
    assert "--remove-orphans" in release_text
    assert "--pull never" in release_text
    assert "--wait" in release_text
    assert "--wait-timeout 120" in release_text


def test_candidate_release_gets_explicit_runtime_verification() -> None:
    release_text = _release_text()

    assert "expected_image=" in release_text
    assert "DEPLOYMENT_IMAGE_REPOSITORY" in release_text
    assert "{{.Config.Image}}" in release_text
    assert "{{.State.Health.Status}}" in release_text
    assert "http://127.0.0.1:8000/health/ready" in release_text
    assert "os.kill(1, 0)" in release_text


def test_failed_candidate_rolls_back_to_previous_sha() -> None:
    release_text = _release_text()

    assert 'if [ -z "$PREVIOUS_SHA" ]; then' in release_text
    assert 'if deploy_sha "$PREVIOUS_SHA" "false"; then' in release_text
    assert '"deployment_failed_rolled_back"' in release_text
    assert '"succeeded"' in release_text
    assert "ROLLBACK_RESULT=succeeded" in release_text
    assert '"rollback_failed"' in release_text


def test_initial_failed_release_is_cleaned_up() -> None:
    release_text = _release_text()

    assert "compose_command down" in release_text
    assert "--remove-orphans" in release_text
    assert '"deployment_failed"' in release_text
    assert '"unavailable"' in release_text


def test_deployment_result_contains_only_sanitized_evidence() -> None:
    release_text = _release_text()

    expected_keys = (
        '"status"',
        '"environment"',
        '"target_commit_sha"',
        '"previous_commit_sha"',
        '"active_commit_sha"',
        '"rollback"',
    )

    for key in expected_keys:
        assert key in release_text

    forbidden_values = (
        "CI_REGISTRY_PASSWORD",
        "DEPLOYMENT_SSH_PRIVATE_KEY",
        "DEPLOYMENT_API_ENV_FILE=",
        "DEPLOYMENT_BOT_ENV_FILE=",
    )

    for value in forbidden_values:
        assert value not in release_text


def test_ci_runs_release_script_and_always_preserves_result() -> None:
    template = _deployment_template()

    assert "sh deployment/release.sh" in template
    assert "when: always" in template
    assert "access: maintainer" in template
    assert "- deployment-result.json" in template
    assert "compose pull" not in template
    assert "compose up" not in template

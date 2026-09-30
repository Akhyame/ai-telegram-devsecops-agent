"""Offline tests for isolated deployment configuration."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import ValidationError

from bot.gitlab_config import get_gitlab_settings
from bot.gitlab_write_config import get_gitlab_write_settings
from deployment.config import (
    DeploymentConfigurationError,
    get_deployment_settings,
)
from deployment.models import DeploymentEnvironment

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = "123456"
_ALLOWED_REF = "main"
_IMAGE_REPOSITORY = "registry.gitlab.com/akhyames/ai-telegram-devsecops-agent"

_ENVIRONMENT_NAMES = (
    "GITLAB_API_URL",
    "GITLAB_PROJECT_ID",
    "GITLAB_DEFAULT_REF",
    "GITLAB_API_TOKEN",
    "GITLAB_WRITE_API_TOKEN",
    "DEPLOYMENT_IMAGE_REPOSITORY",
)


def _valid_token(marker: str) -> str:
    return "".join(
        (
            "gl",
            "pat-",
            marker * 24,
            ".",
            marker.lower() * 24,
        )
    )


@pytest.fixture(autouse=True)
def _isolate_deployment_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)

    for name in _ENVIRONMENT_NAMES:
        monkeypatch.delenv(name, raising=False)

    get_gitlab_settings.cache_clear()
    get_gitlab_write_settings.cache_clear()
    get_deployment_settings.cache_clear()

    yield

    get_gitlab_settings.cache_clear()
    get_gitlab_write_settings.cache_clear()
    get_deployment_settings.cache_clear()


def _configure_valid_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, str]:
    read_token = _valid_token("R")
    write_token = _valid_token("W")

    monkeypatch.setenv("GITLAB_API_URL", _API_URL)
    monkeypatch.setenv("GITLAB_PROJECT_ID", _PROJECT_ID)
    monkeypatch.setenv("GITLAB_DEFAULT_REF", _ALLOWED_REF)
    monkeypatch.setenv("GITLAB_API_TOKEN", read_token)
    monkeypatch.setenv("GITLAB_WRITE_API_TOKEN", write_token)
    monkeypatch.setenv(
        "DEPLOYMENT_IMAGE_REPOSITORY",
        _IMAGE_REPOSITORY,
    )

    return read_token, write_token


def test_valid_settings_use_fixed_deployment_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_valid_environment(monkeypatch)

    settings = get_deployment_settings()

    assert settings.api_url == _API_URL
    assert settings.project_id == int(_PROJECT_ID)
    assert settings.allowed_ref == _ALLOWED_REF
    assert settings.image_repository == _IMAGE_REPOSITORY


@pytest.mark.parametrize(
    "environment",
    (
        DeploymentEnvironment.STAGING,
        DeploymentEnvironment.PRODUCTION,
    ),
)
def test_settings_build_only_typed_fixed_targets(
    monkeypatch: pytest.MonkeyPatch,
    environment: DeploymentEnvironment,
) -> None:
    _configure_valid_environment(monkeypatch)

    target = get_deployment_settings().target_for(environment)

    assert target.environment is environment
    assert target.project_id == int(_PROJECT_ID)
    assert target.ref == _ALLOWED_REF


def test_untyped_environment_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_valid_environment(monkeypatch)

    with pytest.raises(
        TypeError,
        match=r"\ADeployment environment is invalid\.\Z",
    ):
        get_deployment_settings().target_for("staging")


@pytest.mark.parametrize(
    "repository",
    (
        "docker.io/akhyames/project",
        "https://registry.gitlab.com/akhyames/project",
        "registry.gitlab.com/Akhyames/project",
        "registry.gitlab.com/akhyames//project",
        "registry.gitlab.com/akhyames/project:latest",
        " registry.gitlab.com/akhyames/project",
    ),
)
def test_untrusted_image_repository_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    repository: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("DEPLOYMENT_IMAGE_REPOSITORY", repository)

    with pytest.raises(
        DeploymentConfigurationError,
        match=r"\ADeployment configuration is invalid\.\Z",
    ):
        get_deployment_settings()


def test_deployment_settings_are_cached_and_frozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_valid_environment(monkeypatch)

    first = get_deployment_settings()
    second = get_deployment_settings()

    assert first is second

    with pytest.raises(ValidationError):
        first.project_id = 999

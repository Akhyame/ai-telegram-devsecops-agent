"""Offline tests for secure GitLab API configuration."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from bot.gitlab_config import (
    GitLabConfigurationError,
    get_gitlab_settings,
)

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = "123456"
_DEFAULT_REF = "main"
_ENVIRONMENT_NAMES = (
    "GITLAB_API_URL",
    "GITLAB_PROJECT_ID",
    "GITLAB_DEFAULT_REF",
    "GITLAB_API_TOKEN",
)


def _valid_token() -> str:
    return "".join(
        (
            "gl",
            "pat-",
            "A" * 24,
            ".",
            "B" * 24,
        )
    )


@pytest.fixture(autouse=True)
def _isolate_gitlab_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)

    for name in _ENVIRONMENT_NAMES:
        monkeypatch.delenv(name, raising=False)

    get_gitlab_settings.cache_clear()

    yield

    get_gitlab_settings.cache_clear()


def _configure_valid_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    token = _valid_token()

    monkeypatch.setenv("GITLAB_API_URL", _API_URL)
    monkeypatch.setenv("GITLAB_PROJECT_ID", _PROJECT_ID)
    monkeypatch.setenv(
        "GITLAB_DEFAULT_REF",
        _DEFAULT_REF,
    )
    monkeypatch.setenv("GITLAB_API_TOKEN", token)

    return token


def test_valid_gitlab_settings_are_loaded_without_secret_leakage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = _configure_valid_environment(monkeypatch)

    settings = get_gitlab_settings()

    assert settings.api_url == _API_URL
    assert settings.project_id == int(_PROJECT_ID)
    assert settings.default_ref == _DEFAULT_REF
    assert isinstance(settings.api_token, SecretStr)
    assert settings.api_token.get_secret_value() == token
    assert token not in repr(settings)
    assert token not in str(settings.api_token)


def test_missing_configuration_raises_controlled_error() -> None:
    with pytest.raises(
        GitLabConfigurationError,
        match=r"\AGitLab configuration is invalid\.\Z",
    ):
        get_gitlab_settings()


@pytest.mark.parametrize(
    "invalid_url",
    (
        "http://gitlab.com/api/v4",
        "https://example.invalid/api/v4",
        "https://gitlab.com/api/v4/",
    ),
)
def test_untrusted_api_url_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    invalid_url: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("GITLAB_API_URL", invalid_url)

    with pytest.raises(
        GitLabConfigurationError,
        match=r"\AGitLab configuration is invalid\.\Z",
    ):
        get_gitlab_settings()


@pytest.mark.parametrize(
    "invalid_project_id",
    (
        "0",
        "-1",
        "not-a-number",
    ),
)
def test_invalid_project_id_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    invalid_project_id: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv(
        "GITLAB_PROJECT_ID",
        invalid_project_id,
    )

    with pytest.raises(
        GitLabConfigurationError,
        match=r"\AGitLab configuration is invalid\.\Z",
    ):
        get_gitlab_settings()


@pytest.mark.parametrize(
    "unsafe_ref",
    (
        "../main",
        "main?private_token=secret",
        "main branch",
        "feature//unsafe",
        "refs/heads/test.lock",
    ),
)
def test_unsafe_default_ref_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    unsafe_ref: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("GITLAB_DEFAULT_REF", unsafe_ref)

    with pytest.raises(
        GitLabConfigurationError,
        match=r"\AGitLab configuration is invalid\.\Z",
    ):
        get_gitlab_settings()


@pytest.mark.parametrize(
    "invalid_token",
    (
        "too-short",
        ("A" * 24) + " ",
        ("A" * 24) + "\n",
    ),
)
def test_invalid_api_token_is_rejected_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
    invalid_token: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("GITLAB_API_TOKEN", invalid_token)

    with pytest.raises(
        GitLabConfigurationError,
        match=r"\AGitLab configuration is invalid\.\Z",
    ) as error:
        get_gitlab_settings()

    assert invalid_token not in str(error.value)

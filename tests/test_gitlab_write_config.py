"""Offline tests for isolated GitLab write configuration."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from bot.gitlab_config import get_gitlab_settings
from bot.gitlab_write_config import (
    GitLabWriteConfigurationError,
    get_gitlab_write_settings,
)

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = "123456"
_ALLOWED_REF = "main"
_ENVIRONMENT_NAMES = (
    "GITLAB_API_URL",
    "GITLAB_PROJECT_ID",
    "GITLAB_DEFAULT_REF",
    "GITLAB_API_TOKEN",
    "GITLAB_WRITE_API_TOKEN",
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
def _isolate_gitlab_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)

    for name in _ENVIRONMENT_NAMES:
        monkeypatch.delenv(name, raising=False)

    get_gitlab_settings.cache_clear()
    get_gitlab_write_settings.cache_clear()

    yield

    get_gitlab_settings.cache_clear()
    get_gitlab_write_settings.cache_clear()


def _configure_shared_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITLAB_API_URL", _API_URL)
    monkeypatch.setenv("GITLAB_PROJECT_ID", _PROJECT_ID)
    monkeypatch.setenv("GITLAB_DEFAULT_REF", _ALLOWED_REF)


def _configure_valid_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[str, str]:
    _configure_shared_environment(monkeypatch)
    read_token = _valid_token("R")
    write_token = _valid_token("W")
    monkeypatch.setenv("GITLAB_API_TOKEN", read_token)
    monkeypatch.setenv("GITLAB_WRITE_API_TOKEN", write_token)

    return read_token, write_token


def test_valid_write_settings_use_a_distinct_masked_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_token, write_token = _configure_valid_environment(monkeypatch)

    settings = get_gitlab_write_settings()

    assert settings.api_url == _API_URL
    assert settings.project_id == int(_PROJECT_ID)
    assert settings.allowed_ref == _ALLOWED_REF
    assert isinstance(settings.api_token, SecretStr)
    assert settings.api_token.get_secret_value() == write_token
    assert write_token != read_token
    assert write_token not in repr(settings)
    assert write_token not in str(settings.api_token)


def test_read_token_is_not_used_as_write_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_shared_environment(monkeypatch)
    read_token = _valid_token("R")
    monkeypatch.setenv("GITLAB_API_TOKEN", read_token)

    with pytest.raises(
        GitLabWriteConfigurationError,
        match=r"\AGitLab write configuration is invalid\.\Z",
    ) as error:
        get_gitlab_write_settings()

    assert read_token not in str(error.value)


def test_reusing_read_token_for_writes_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_shared_environment(monkeypatch)
    reused_token = _valid_token("S")
    monkeypatch.setenv("GITLAB_API_TOKEN", reused_token)
    monkeypatch.setenv("GITLAB_WRITE_API_TOKEN", reused_token)

    with pytest.raises(
        GitLabWriteConfigurationError,
        match=r"\AGitLab write configuration is invalid\.\Z",
    ) as error:
        get_gitlab_write_settings()

    assert reused_token not in str(error.value)


@pytest.mark.parametrize(
    "invalid_url",
    (
        "http://gitlab.com/api/v4",
        "https://example.invalid/api/v4",
        "https://gitlab.com/api/v4/",
    ),
)
def test_untrusted_write_api_url_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    invalid_url: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("GITLAB_API_URL", invalid_url)

    with pytest.raises(
        GitLabWriteConfigurationError,
        match=r"\AGitLab write configuration is invalid\.\Z",
    ):
        get_gitlab_write_settings()


@pytest.mark.parametrize(
    "invalid_project_id",
    (
        "0",
        "-1",
        "not-a-number",
    ),
)
def test_invalid_write_project_id_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    invalid_project_id: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("GITLAB_PROJECT_ID", invalid_project_id)

    with pytest.raises(
        GitLabWriteConfigurationError,
        match=r"\AGitLab write configuration is invalid\.\Z",
    ):
        get_gitlab_write_settings()


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
def test_unsafe_write_ref_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    unsafe_ref: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("GITLAB_DEFAULT_REF", unsafe_ref)

    with pytest.raises(
        GitLabWriteConfigurationError,
        match=r"\AGitLab write configuration is invalid\.\Z",
    ):
        get_gitlab_write_settings()


@pytest.mark.parametrize(
    "invalid_token",
    (
        "too-short",
        ("A" * 24) + " ",
        ("A" * 24) + "\n",
    ),
)
def test_invalid_write_token_is_rejected_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
    invalid_token: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv("GITLAB_WRITE_API_TOKEN", invalid_token)

    with pytest.raises(
        GitLabWriteConfigurationError,
        match=r"\AGitLab write configuration is invalid\.\Z",
    ) as error:
        get_gitlab_write_settings()

    assert invalid_token not in str(error.value)

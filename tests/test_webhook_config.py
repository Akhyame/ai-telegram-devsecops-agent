"""Offline tests for secure GitLab webhook configuration."""

import base64
from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr

from sample_app.webhook_config import (
    ALLOWED_GITLAB_WEBHOOK_EVENTS,
    GITLAB_WEBHOOK_INSTANCE,
    MAX_WEBHOOK_BODY_BYTES,
    MAX_WEBHOOK_TIMESTAMP_AGE_SECONDS,
    WebhookConfigurationError,
    get_webhook_settings,
)

_PROJECT_ID = "123456"
_ENVIRONMENT_NAMES = (
    "GITLAB_PROJECT_ID",
    "GITLAB_WEBHOOK_SIGNING_TOKEN",
)


def _valid_signing_token() -> str:
    encoded_key = base64.b64encode(b"S" * 32).decode("ascii")
    return f"whsec_{encoded_key}"


@pytest.fixture(autouse=True)
def _isolate_webhook_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)

    for name in _ENVIRONMENT_NAMES:
        monkeypatch.delenv(
            name,
            raising=False,
        )

    get_webhook_settings.cache_clear()

    yield

    get_webhook_settings.cache_clear()


def _configure_valid_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> str:
    token = _valid_signing_token()

    monkeypatch.setenv(
        "GITLAB_PROJECT_ID",
        _PROJECT_ID,
    )
    monkeypatch.setenv(
        "GITLAB_WEBHOOK_SIGNING_TOKEN",
        token,
    )

    return token


def test_valid_webhook_settings_are_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = _configure_valid_environment(monkeypatch)

    settings = get_webhook_settings()

    assert settings.project_id == int(_PROJECT_ID)
    assert isinstance(
        settings.signing_token,
        SecretStr,
    )
    assert settings.signing_token.get_secret_value() == token
    assert token not in repr(settings)
    assert token not in str(settings.signing_token)


def test_security_limits_are_fixed() -> None:
    assert GITLAB_WEBHOOK_INSTANCE == "https://gitlab.com"
    assert MAX_WEBHOOK_BODY_BYTES == 262_144
    assert MAX_WEBHOOK_TIMESTAMP_AGE_SECONDS == 300
    assert ALLOWED_GITLAB_WEBHOOK_EVENTS == {
        "Pipeline Hook",
    }


def test_missing_configuration_is_controlled() -> None:
    with pytest.raises(
        WebhookConfigurationError,
        match=(
            r"\AWebhook configuration "
            r"is invalid\.\Z"
        ),
    ):
        get_webhook_settings()


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
        WebhookConfigurationError,
        match=(
            r"\AWebhook configuration "
            r"is invalid\.\Z"
        ),
    ):
        get_webhook_settings()


@pytest.mark.parametrize(
    "invalid_token",
    (
        "missing-prefix",
        "whsec_not-base64!",
        ("whsec_" + base64.b64encode(b"A" * 31).decode("ascii")),
        ("whsec_" + base64.b64encode(b"A" * 33).decode("ascii")),
        ("whsec_" + base64.b64encode(b"A" * 32).decode("ascii") + " "),
    ),
)
def test_invalid_signing_token_is_rejected_safely(
    monkeypatch: pytest.MonkeyPatch,
    invalid_token: str,
) -> None:
    _configure_valid_environment(monkeypatch)
    monkeypatch.setenv(
        "GITLAB_WEBHOOK_SIGNING_TOKEN",
        invalid_token,
    )

    with pytest.raises(
        WebhookConfigurationError,
        match=(
            r"\AWebhook configuration "
            r"is invalid\.\Z"
        ),
    ) as error:
        get_webhook_settings()

    assert invalid_token not in str(error.value)

"""Validated and secret-safe configuration for GitLab write actions."""

import re
from functools import lru_cache
from hmac import compare_digest

from pydantic import (
    Field,
    PositiveInt,
    SecretStr,
    ValidationError,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from bot.gitlab_config import (
    GitLabConfigurationError,
    get_gitlab_settings,
)

_ALLOWED_API_URL = "https://gitlab.com/api/v4"
_SAFE_REF_PATTERN = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9])?\Z")


class GitLabWriteConfigurationError(RuntimeError):
    """Raised when GitLab write configuration is unavailable or unsafe."""


class GitLabWriteSettings(BaseSettings):
    """Validated settings for one project-scoped GitLab write capability."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    api_url: str = Field(
        validation_alias="GITLAB_API_URL",
    )
    project_id: PositiveInt = Field(
        validation_alias="GITLAB_PROJECT_ID",
    )
    allowed_ref: str = Field(
        validation_alias="GITLAB_DEFAULT_REF",
    )
    api_token: SecretStr = Field(
        validation_alias="GITLAB_WRITE_API_TOKEN",
    )

    @field_validator("api_url")
    @classmethod
    def _validate_api_url(
        cls,
        value: str,
    ) -> str:
        if value != _ALLOWED_API_URL:
            raise ValueError("GitLab write API URL is not allowed.")

        return value

    @field_validator("allowed_ref")
    @classmethod
    def _validate_allowed_ref(
        cls,
        value: str,
    ) -> str:
        unsafe_sequences = (
            "..",
            "//",
            "@{",
        )

        if (
            _SAFE_REF_PATTERN.fullmatch(value) is None
            or any(sequence in value for sequence in unsafe_sequences)
            or value.endswith(".lock")
        ):
            raise ValueError("GitLab write ref is invalid.")

        return value

    @field_validator("api_token")
    @classmethod
    def _validate_api_token(
        cls,
        value: SecretStr,
    ) -> SecretStr:
        secret = value.get_secret_value()

        if (
            not 20 <= len(secret) <= 512
            or secret != secret.strip()
            or not all(33 <= ord(character) <= 126 for character in secret)
        ):
            raise ValueError("GitLab write API token is invalid.")

        return value


@lru_cache(maxsize=1)
def get_gitlab_write_settings() -> GitLabWriteSettings:
    """Load an isolated write credential and reject read-token reuse."""

    try:
        settings = GitLabWriteSettings()
        read_settings = get_gitlab_settings()
    except (
        GitLabConfigurationError,
        OSError,
        ValidationError,
    ) as exc:
        raise GitLabWriteConfigurationError("GitLab write configuration is invalid.") from exc

    if compare_digest(
        settings.api_token.get_secret_value(),
        read_settings.api_token.get_secret_value(),
    ):
        raise GitLabWriteConfigurationError("GitLab write configuration is invalid.") from None

    return settings

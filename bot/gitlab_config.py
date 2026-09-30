"""Validated and secret-safe GitLab API configuration."""

import re
from functools import lru_cache

from pydantic import (
    Field,
    PositiveInt,
    SecretStr,
    ValidationError,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

_ALLOWED_API_URL = "https://gitlab.com/api/v4"
_SAFE_REF_PATTERN = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9])?\Z")


class GitLabConfigurationError(RuntimeError):
    """Raised when GitLab API configuration is invalid."""


class GitLabSettings(BaseSettings):
    """Validated settings for one project-scoped GitLab API client."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    api_url: str = Field(
        validation_alias="GITLAB_API_URL",
    )
    project_id: PositiveInt = Field(
        validation_alias="GITLAB_PROJECT_ID",
    )
    default_ref: str = Field(
        validation_alias="GITLAB_DEFAULT_REF",
    )
    api_token: SecretStr = Field(
        validation_alias="GITLAB_API_TOKEN",
    )

    @field_validator("api_url")
    @classmethod
    def _validate_api_url(
        cls,
        value: str,
    ) -> str:
        if value != _ALLOWED_API_URL:
            raise ValueError("GitLab API URL is not allowed.")

        return value

    @field_validator("default_ref")
    @classmethod
    def _validate_default_ref(
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
            raise ValueError("GitLab default ref is invalid.")

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
            raise ValueError("GitLab API token is invalid.")

        return value


@lru_cache(maxsize=1)
def get_gitlab_settings() -> GitLabSettings:
    """Load validated GitLab settings with a controlled failure."""

    try:
        return GitLabSettings()
    except ValidationError as exc:
        raise GitLabConfigurationError("GitLab configuration is invalid.") from exc

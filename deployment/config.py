"""Validated and secret-safe configuration for controlled deployments."""

import re
from functools import lru_cache

from pydantic import (
    Field,
    PositiveInt,
    ValidationError,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from bot.gitlab_config import (
    GitLabConfigurationError,
    get_gitlab_settings,
)
from bot.gitlab_write_config import (
    GitLabWriteConfigurationError,
    get_gitlab_write_settings,
)
from deployment.models import (
    DeploymentEnvironment,
    DeploymentTarget,
)

_ALLOWED_API_URL = "https://gitlab.com/api/v4"
_IMAGE_REGISTRY_PREFIX = "registry.gitlab.com/"
_IMAGE_SEGMENT_PATTERN = re.compile(r"\A[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?\Z")
_SAFE_REF_PATTERN = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9])?\Z")


class DeploymentConfigurationError(RuntimeError):
    """Raised when deployment configuration is unavailable or unsafe."""


class DeploymentSettings(BaseSettings):
    """Validated settings for one fixed project deployment capability."""

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
    image_repository: str = Field(
        validation_alias="DEPLOYMENT_IMAGE_REPOSITORY",
        min_length=1,
        max_length=255,
    )

    @field_validator("api_url")
    @classmethod
    def _validate_api_url(
        cls,
        value: str,
    ) -> str:
        if value != _ALLOWED_API_URL:
            raise ValueError("Deployment API URL is not allowed.")

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
            raise ValueError("Deployment ref is invalid.")

        return value

    @field_validator("image_repository")
    @classmethod
    def _validate_image_repository(
        cls,
        value: str,
    ) -> str:
        if not value.startswith(_IMAGE_REGISTRY_PREFIX):
            raise ValueError("Deployment image repository is not allowed.")

        path = value.removeprefix(_IMAGE_REGISTRY_PREFIX)
        segments = path.split("/")

        if len(segments) < 2 or any(
            _IMAGE_SEGMENT_PATTERN.fullmatch(segment) is None for segment in segments
        ):
            raise ValueError("Deployment image repository is invalid.")

        return value

    def target_for(
        self,
        environment: DeploymentEnvironment,
    ) -> DeploymentTarget:
        """Build one fixed, validated deployment target."""

        if not isinstance(environment, DeploymentEnvironment):
            raise TypeError("Deployment environment is invalid.")

        return DeploymentTarget(
            environment=environment,
            project_id=self.project_id,
            ref=self.allowed_ref,
        )


@lru_cache(maxsize=1)
def get_deployment_settings() -> DeploymentSettings:
    """Load an isolated deployment credential and reject credential reuse."""

    try:
        settings = DeploymentSettings()
        read_settings = get_gitlab_settings()
        write_settings = get_gitlab_write_settings()
    except (
        GitLabConfigurationError,
        GitLabWriteConfigurationError,
        OSError,
        ValidationError,
    ) as exc:
        raise DeploymentConfigurationError("Deployment configuration is invalid.") from exc

    if (
        settings.api_url != read_settings.api_url
        or settings.api_url != write_settings.api_url
        or settings.project_id != read_settings.project_id
        or settings.project_id != write_settings.project_id
        or settings.allowed_ref != read_settings.default_ref
        or settings.allowed_ref != write_settings.allowed_ref
    ):
        raise DeploymentConfigurationError("Deployment configuration is invalid.") from None

    return settings

"""Validated and secret-safe GitLab webhook configuration."""

import base64
import binascii
from functools import lru_cache

from pydantic import (
    Field,
    PositiveInt,
    SecretStr,
    ValidationError,
    field_validator,
)
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)

GITLAB_WEBHOOK_INSTANCE = "https://gitlab.com"
MAX_WEBHOOK_BODY_BYTES = 262_144
MAX_WEBHOOK_TIMESTAMP_AGE_SECONDS = 300
ALLOWED_GITLAB_WEBHOOK_EVENTS = frozenset(
    {
        "Pipeline Hook",
    }
)
_WEBHOOK_KEY_PREFIX = "whsec_"
_SIGNING_KEY_BYTES = 32


class WebhookConfigurationError(RuntimeError):
    """Raised when GitLab webhook configuration is invalid."""


class GitLabWebhookSettings(BaseSettings):
    """Validated settings for one project-scoped webhook receiver."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        frozen=True,
    )

    project_id: PositiveInt = Field(
        validation_alias="GITLAB_PROJECT_ID",
    )
    signing_token: SecretStr = Field(
        validation_alias=("GITLAB_WEBHOOK_SIGNING_TOKEN"),
    )

    @field_validator("signing_token")
    @classmethod
    def _validate_signing_token(
        cls,
        value: SecretStr,
    ) -> SecretStr:
        secret = value.get_secret_value()

        if secret != secret.strip() or not secret.startswith(_WEBHOOK_KEY_PREFIX):
            raise ValueError("GitLab webhook signing token is invalid.")

        encoded_key = secret.removeprefix(_WEBHOOK_KEY_PREFIX)

        try:
            decoded_key = base64.b64decode(
                encoded_key,
                validate=True,
            )
        except (
            binascii.Error,
            ValueError,
        ) as exc:
            raise ValueError("GitLab webhook signing token is invalid.") from exc

        canonical_key = base64.b64encode(decoded_key).decode("ascii")

        if len(decoded_key) != _SIGNING_KEY_BYTES or canonical_key != encoded_key:
            raise ValueError("GitLab webhook signing token is invalid.")

        return value


@lru_cache(maxsize=1)
def get_webhook_settings() -> GitLabWebhookSettings:
    """Load webhook settings with a controlled failure."""

    try:
        return GitLabWebhookSettings()
    except ValidationError as exc:
        raise WebhookConfigurationError("Webhook configuration is invalid.") from exc

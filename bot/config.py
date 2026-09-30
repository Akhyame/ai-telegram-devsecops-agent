"""Secure Telegram bot configuration loaded from the environment."""

import re
from functools import lru_cache
from typing import Annotated, Self

from pydantic import (
    AnyHttpUrl,
    BeforeValidator,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

MAX_TELEGRAM_USER_ID = (1 << 52) - 1

_TOKEN_PATTERN = re.compile(r"[1-9][0-9]{0,19}:[A-Za-z0-9_-]{20,200}")
_USER_ID_PATTERN = re.compile(r"[1-9][0-9]*")


def _parse_user_ids(value: object) -> object:
    """Parse a comma-separated list into unique numeric Telegram user IDs."""

    if not isinstance(value, str):
        return value

    user_ids: set[int] = set()

    for raw_item in value.split(","):
        item = raw_item.strip()

        if _USER_ID_PATTERN.fullmatch(item) is None:
            raise ValueError("Telegram user ID list configuration is invalid")

        user_id = int(item)

        if user_id > MAX_TELEGRAM_USER_ID or user_id in user_ids:
            raise ValueError("Telegram user ID list configuration is invalid")

        user_ids.add(user_id)

    return frozenset(user_ids)


TelegramUserIds = Annotated[
    frozenset[int],
    NoDecode,
    BeforeValidator(_parse_user_ids),
]


class BotConfigurationError(RuntimeError):
    """Controlled error for missing or invalid bot configuration."""


class BotSettings(BaseSettings):
    """Validated Telegram bot settings with masked secret values."""

    model_config = SettingsConfigDict(
        env_prefix="TELEGRAM_BOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        case_sensitive=False,
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    token: SecretStr
    allowed_user_ids: TelegramUserIds = Field(
        default_factory=frozenset,
        validation_alias="TELEGRAM_ALLOWED_USER_IDS",
    )
    operator_user_ids: TelegramUserIds = Field(
        default_factory=frozenset,
        validation_alias="TELEGRAM_OPERATOR_USER_IDS",
    )
    admin_user_ids: TelegramUserIds = Field(
        default_factory=frozenset,
        validation_alias="TELEGRAM_ADMIN_USER_IDS",
    )
    staging_site_url: AnyHttpUrl | None = Field(
        default=None,
        validation_alias="STAGING_SITE_URL",
    )

    @model_validator(mode="after")
    def validate_role_assignments(self) -> Self:
        """Require unambiguous privileged roles inside the base allowlist."""

        privileged_user_ids = self.operator_user_ids | self.admin_user_ids

        if not privileged_user_ids.issubset(self.allowed_user_ids):
            raise ValueError("Telegram role assignments configuration is invalid")

        if self.operator_user_ids & self.admin_user_ids:
            raise ValueError("Telegram role assignments configuration is invalid")

        return self

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: SecretStr) -> SecretStr:
        """Reject malformed tokens without including their value in errors."""

        if _TOKEN_PATTERN.fullmatch(value.get_secret_value()) is None:
            raise ValueError("Telegram bot token has an invalid format")

        return value

    @field_validator("staging_site_url")
    @classmethod
    def validate_staging_site_url(
        cls,
        value: AnyHttpUrl | None,
    ) -> AnyHttpUrl | None:
        """Reject URLs that could expose embedded credentials or dynamic data."""

        if value is None:
            return None

        if (
            value.username is not None
            or value.password is not None
            or value.query is not None
            or value.fragment is not None
        ):
            raise ValueError("Staging site URL configuration is invalid")

        return value


@lru_cache
def get_bot_settings() -> BotSettings:
    """Load one validated settings instance with a controlled public error."""

    try:
        return BotSettings()
    except (OSError, ValueError):
        raise BotConfigurationError("Telegram bot configuration is invalid.") from None

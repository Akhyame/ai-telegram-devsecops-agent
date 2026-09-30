"""Validated configuration for local-only AI inference."""

from functools import lru_cache

from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ALLOWED_PROVIDER = "ollama-local"
_ALLOWED_API_URL = "http://127.0.0.1:11434/api"
_ALLOWED_DEPLOYMENT_API_URL = "http://192.168.220.1:11434/api"
_ALLOWED_API_URLS = frozenset(
    {
        _ALLOWED_API_URL,
        _ALLOWED_DEPLOYMENT_API_URL,
    }
)
_ALLOWED_MODEL = "qwen3.5:4b"


class AIConfigurationError(RuntimeError):
    """Raised when the local AI configuration is unavailable or unsafe."""


class AISettings(BaseSettings):
    """Allow only one bounded local Ollama inference capability."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        frozen=True,
        hide_input_in_errors=True,
    )

    provider: str = Field(
        default=_ALLOWED_PROVIDER,
        validation_alias="AI_PROVIDER",
    )
    api_url: str = Field(
        default=_ALLOWED_API_URL,
        validation_alias="OLLAMA_API_URL",
    )
    model: str = Field(
        default=_ALLOWED_MODEL,
        validation_alias="OLLAMA_MODEL",
    )
    request_timeout_seconds: int = Field(
        default=60,
        ge=10,
        le=120,
        validation_alias="AI_REQUEST_TIMEOUT_SECONDS",
    )
    max_output_chars: int = Field(
        default=1200,
        ge=200,
        le=2000,
        validation_alias="AI_MAX_OUTPUT_CHARS",
    )

    @field_validator("provider")
    @classmethod
    def _validate_provider(
        cls,
        value: str,
    ) -> str:
        if value != _ALLOWED_PROVIDER:
            raise ValueError("AI provider is not allowed.")

        return value

    @field_validator("api_url")
    @classmethod
    def _validate_api_url(
        cls,
        value: str,
    ) -> str:
        if value not in _ALLOWED_API_URLS:
            raise ValueError("AI API URL is not allowed.")

        return value

    @field_validator("model")
    @classmethod
    def _validate_model(
        cls,
        value: str,
    ) -> str:
        if value != _ALLOWED_MODEL:
            raise ValueError("AI model is not allowed.")

        return value


@lru_cache(maxsize=1)
def get_ai_settings() -> AISettings:
    """Load and cache the validated local AI settings."""

    try:
        return AISettings()
    except (
        OSError,
        ValidationError,
    ):
        raise AIConfigurationError("Local AI configuration is invalid.") from None

"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


class Settings(BaseSettings):
    """Validated, non-secret application settings."""

    model_config = SettingsConfigDict(
        env_prefix="SAMPLE_APP_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        frozen=True,
    )

    app_name: str = "AI DevSecOps Sample Application"
    app_version: str = "0.1.0"
    environment: Environment = "development"
    log_level: LogLevel = "INFO"


@lru_cache
def get_settings() -> Settings:
    """Return one cached settings instance per application process."""

    return Settings()

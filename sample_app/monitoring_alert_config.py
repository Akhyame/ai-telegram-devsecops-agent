"""Validated configuration for internal Alertmanager notifications."""

import base64
import binascii
from functools import lru_cache

from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MONITORING_ALERT_RECEIVER_PATH = "/internal/monitoring/alerts"

MAX_MONITORING_ALERT_BODY_BYTES = 65_536
MAX_MONITORING_ALERTS_PER_NOTIFICATION = 10

ALLOWED_MONITORING_ALERT_NAMES = frozenset(
    {
        "SampleAppUnavailable",
        "SampleAppHighServerErrors",
        "SampleAppHighLatency",
        "RealFastAPIUnavailable",
        "RealFastAPIHighServerErrors",
        "RealFastAPIHighLatency",
    }
)

ALLOWED_MONITORING_ALERT_STATUSES = frozenset(
    {
        "firing",
        "resolved",
    }
)

_ALERT_RECEIVER_TOKEN_PREFIX = "amsec_"  # noqa: S105 - public format prefix, not a credential
_ALERT_RECEIVER_KEY_BYTES = 32


class MonitoringAlertConfigurationError(RuntimeError):
    """Raised when monitoring alert receiver configuration is invalid."""


class MonitoringAlertSettings(BaseSettings):
    """Validated secret settings for the internal Alertmanager receiver."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
        frozen=True,
    )

    receiver_token: SecretStr = Field(
        validation_alias="ALERTMANAGER_RECEIVER_TOKEN",
    )

    @field_validator("receiver_token")
    @classmethod
    def _validate_receiver_token(
        cls,
        value: SecretStr,
    ) -> SecretStr:
        secret = value.get_secret_value()

        if secret != secret.strip() or not secret.startswith(_ALERT_RECEIVER_TOKEN_PREFIX):
            raise ValueError("Alertmanager receiver token is invalid.")

        encoded_key = secret.removeprefix(_ALERT_RECEIVER_TOKEN_PREFIX)

        try:
            decoded_key = base64.b64decode(
                encoded_key,
                validate=True,
            )
        except (
            binascii.Error,
            ValueError,
        ) as exc:
            raise ValueError("Alertmanager receiver token is invalid.") from exc

        canonical_key = base64.b64encode(decoded_key).decode("ascii")

        if len(decoded_key) != _ALERT_RECEIVER_KEY_BYTES or canonical_key != encoded_key:
            raise ValueError("Alertmanager receiver token is invalid.")

        return value


@lru_cache(maxsize=1)
def get_monitoring_alert_settings() -> MonitoringAlertSettings:
    """Load the receiver secret with controlled failure."""

    try:
        return MonitoringAlertSettings()
    except ValidationError as exc:
        raise MonitoringAlertConfigurationError(
            "Monitoring alert receiver configuration is invalid."
        ) from exc

"""Strict normalization for internal Alertmanager webhook payloads."""

from dataclasses import dataclass
from typing import Literal

from sample_app.monitoring_alert_config import (
    ALLOWED_MONITORING_ALERT_NAMES,
    ALLOWED_MONITORING_ALERT_STATUSES,
    MAX_MONITORING_ALERTS_PER_NOTIFICATION,
)

MONITORING_ALERT_RECEIVER_NAME = "monitoring-webhook"
MONITORING_ALERT_WEBHOOK_VERSION = "4"

_MAX_LABEL_COUNT = 16
_MAX_ANNOTATION_COUNT = 16
_MAX_KEY_LENGTH = 64
_MAX_LABEL_VALUE_LENGTH = 256
_MAX_ANNOTATION_VALUE_LENGTH = 512

_EXPECTED_ALERT_METADATA = {
    "SampleAppUnavailable": {
        "severity": "critical",
        "service": "sample-app",
    },
    "SampleAppHighServerErrors": {
        "severity": "warning",
        "service": "sample-app",
    },
    "SampleAppHighLatency": {
        "severity": "warning",
        "service": "sample-app",
    },
    "RealFastAPIUnavailable": {
        "severity": "critical",
        "service": "real-fastapi-staging",
    },
    "RealFastAPIHighServerErrors": {
        "severity": "warning",
        "service": "real-fastapi-staging",
    },
    "RealFastAPIHighLatency": {
        "severity": "warning",
        "service": "real-fastapi-staging",
    },
}


class MonitoringAlertRequestError(ValueError):
    """Raised when an Alertmanager notification is not accepted."""


@dataclass(frozen=True, slots=True)
class MonitoringAlertEvent:
    """Minimal deterministic alert data safe for notification logic."""

    alert_name: str
    status: Literal["firing", "resolved"]
    severity: str
    service: str


def _require_bounded_string_mapping(
    value: object,
    *,
    maximum_items: int,
    maximum_value_length: int,
) -> dict[str, str]:
    if not isinstance(value, dict):
        raise MonitoringAlertRequestError("Monitoring alert mapping is invalid.")

    if len(value) > maximum_items:
        raise MonitoringAlertRequestError("Monitoring alert mapping is invalid.")

    normalized: dict[str, str] = {}

    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not key
            or len(key) > _MAX_KEY_LENGTH
            or len(item) > maximum_value_length
        ):
            raise MonitoringAlertRequestError("Monitoring alert mapping is invalid.")

        normalized[key] = item

    return normalized


def _normalize_alert(
    value: object,
) -> MonitoringAlertEvent:
    if not isinstance(value, dict):
        raise MonitoringAlertRequestError("Monitoring alert entry is invalid.")

    status = value.get("status")

    if not isinstance(status, str) or status not in ALLOWED_MONITORING_ALERT_STATUSES:
        raise MonitoringAlertRequestError("Monitoring alert status is invalid.")

    labels = _require_bounded_string_mapping(
        value.get("labels"),
        maximum_items=_MAX_LABEL_COUNT,
        maximum_value_length=_MAX_LABEL_VALUE_LENGTH,
    )

    annotations = value.get("annotations", {})

    _require_bounded_string_mapping(
        annotations,
        maximum_items=_MAX_ANNOTATION_COUNT,
        maximum_value_length=_MAX_ANNOTATION_VALUE_LENGTH,
    )

    alert_name = labels.get("alertname")
    severity = labels.get("severity")
    service = labels.get("service")

    if alert_name not in ALLOWED_MONITORING_ALERT_NAMES or not isinstance(alert_name, str):
        raise MonitoringAlertRequestError("Monitoring alert name is invalid.")

    expected = _EXPECTED_ALERT_METADATA[alert_name]

    if severity != expected["severity"]:
        raise MonitoringAlertRequestError("Monitoring alert severity is invalid.")

    if service != expected["service"]:
        raise MonitoringAlertRequestError("Monitoring alert service is invalid.")

    return MonitoringAlertEvent(
        alert_name=alert_name,
        status=status,
        severity=severity,
        service=service,
    )


def normalize_monitoring_alert_payload(
    payload: object,
) -> tuple[MonitoringAlertEvent, ...]:
    """Return only allowlisted normalized alert evidence."""

    if not isinstance(payload, dict):
        raise MonitoringAlertRequestError("Monitoring alert payload is invalid.")

    if payload.get("version") != MONITORING_ALERT_WEBHOOK_VERSION:
        raise MonitoringAlertRequestError("Monitoring alert webhook version is invalid.")

    if payload.get("receiver") != MONITORING_ALERT_RECEIVER_NAME:
        raise MonitoringAlertRequestError("Monitoring alert receiver is invalid.")

    group_status = payload.get("status")

    if group_status not in ALLOWED_MONITORING_ALERT_STATUSES:
        raise MonitoringAlertRequestError("Monitoring alert group status is invalid.")

    truncated_alerts = payload.get("truncatedAlerts", 0)

    if (
        isinstance(truncated_alerts, bool)
        or not isinstance(truncated_alerts, int)
        or truncated_alerts != 0
    ):
        raise MonitoringAlertRequestError("Truncated monitoring alerts are not accepted.")

    alerts = payload.get("alerts")

    if (
        not isinstance(alerts, list)
        or not alerts
        or len(alerts) > MAX_MONITORING_ALERTS_PER_NOTIFICATION
    ):
        raise MonitoringAlertRequestError("Monitoring alert collection is invalid.")

    normalized: list[MonitoringAlertEvent] = []
    seen: set[tuple[str, str, str, str]] = set()

    for alert in alerts:
        event = _normalize_alert(alert)

        key = (
            event.alert_name,
            event.status,
            event.severity,
            event.service,
        )

        if key in seen:
            continue

        seen.add(key)
        normalized.append(event)

    if not normalized:
        raise MonitoringAlertRequestError("Monitoring alert collection is invalid.")

    return tuple(normalized)

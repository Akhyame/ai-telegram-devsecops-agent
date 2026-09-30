import pytest

from sample_app.monitoring_alert_events import (
    MONITORING_ALERT_RECEIVER_NAME,
    MONITORING_ALERT_WEBHOOK_VERSION,
    MonitoringAlertEvent,
    MonitoringAlertRequestError,
    normalize_monitoring_alert_payload,
)


def _alert(
    *,
    name: str = "SampleAppUnavailable",
    status: str = "firing",
    severity: str = "critical",
    service: str = "sample-app",
) -> dict[str, object]:
    return {
        "status": status,
        "labels": {
            "alertname": name,
            "severity": severity,
            "service": service,
            "job": "sample-app",
            "instance": "api:8000",
        },
        "annotations": {
            "summary": "ignored summary",
            "description": "ignored description",
        },
        "startsAt": "2026-09-01T17:00:00Z",
        "generatorURL": "http://internal.example/",
        "fingerprint": "0123456789abcdef",
    }


def _payload(
    alerts: list[dict[str, object]],
    *,
    status: str = "firing",
) -> dict[str, object]:
    return {
        "version": MONITORING_ALERT_WEBHOOK_VERSION,
        "receiver": MONITORING_ALERT_RECEIVER_NAME,
        "status": status,
        "truncatedAlerts": 0,
        "groupLabels": {
            "alertname": "SampleAppUnavailable",
        },
        "commonLabels": {},
        "commonAnnotations": {},
        "externalURL": "http://alertmanager:9093",
        "alerts": alerts,
    }


def test_valid_payload_is_reduced_to_minimal_event() -> None:
    events = normalize_monitoring_alert_payload(_payload([_alert()]))

    assert events == (
        MonitoringAlertEvent(
            alert_name="SampleAppUnavailable",
            status="firing",
            severity="critical",
            service="sample-app",
        ),
    )


def test_extra_runtime_labels_are_not_forwarded() -> None:
    events = normalize_monitoring_alert_payload(_payload([_alert()]))

    rendered = repr(events)

    assert "api:8000" not in rendered
    assert "instance" not in rendered
    assert "job" not in rendered


def test_annotations_and_internal_urls_are_not_forwarded() -> None:
    events = normalize_monitoring_alert_payload(_payload([_alert()]))

    rendered = repr(events)

    assert "ignored summary" not in rendered
    assert "ignored description" not in rendered
    assert "internal.example" not in rendered
    assert "alertmanager:9093" not in rendered


@pytest.mark.parametrize(
    ("name", "severity"),
    [
        ("UnknownAlert", "warning"),
        ("SampleAppUnavailable", "warning"),
        ("SampleAppHighServerErrors", "critical"),
        ("SampleAppHighLatency", "critical"),
    ],
)
def test_unknown_or_mismatched_alert_metadata_is_rejected(
    name: str,
    severity: str,
) -> None:
    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(
            _payload(
                [
                    _alert(
                        name=name,
                        severity=severity,
                    )
                ]
            )
        )


@pytest.mark.parametrize(
    "service",
    [
        "",
        "other-service",
        "sample-app ",
    ],
)
def test_invalid_service_is_rejected(service: str) -> None:
    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(
            _payload(
                [
                    _alert(
                        service=service,
                    )
                ]
            )
        )


@pytest.mark.parametrize(
    "status",
    [
        "",
        "pending",
        "inactive",
        "unknown",
    ],
)
def test_invalid_alert_status_is_rejected(status: str) -> None:
    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(
            _payload(
                [
                    _alert(
                        status=status,
                    )
                ]
            )
        )


def test_resolved_alert_is_accepted() -> None:
    events = normalize_monitoring_alert_payload(
        _payload(
            [
                _alert(
                    status="resolved",
                )
            ],
            status="resolved",
        )
    )

    assert events[0].status == "resolved"


def test_wrong_webhook_version_is_rejected() -> None:
    payload = _payload([_alert()])
    payload["version"] = "3"

    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(payload)


def test_wrong_receiver_is_rejected() -> None:
    payload = _payload([_alert()])
    payload["receiver"] = "other-receiver"

    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(payload)


def test_truncated_alerts_fail_closed() -> None:
    payload = _payload([_alert()])
    payload["truncatedAlerts"] = 1

    with pytest.raises(
        MonitoringAlertRequestError,
        match="Truncated monitoring alerts",
    ):
        normalize_monitoring_alert_payload(payload)


def test_empty_alert_collection_is_rejected() -> None:
    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(_payload([]))


def test_alert_collection_is_bounded() -> None:
    payload = _payload([_alert() for _ in range(11)])

    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(payload)


def test_duplicate_normalized_events_are_collapsed() -> None:
    events = normalize_monitoring_alert_payload(
        _payload(
            [
                _alert(),
                _alert(),
            ]
        )
    )

    assert len(events) == 1


def test_malformed_labels_are_rejected() -> None:
    alert = _alert()
    alert["labels"] = ["not", "a", "mapping"]

    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(_payload([alert]))


def test_oversized_annotation_value_is_rejected() -> None:
    alert = _alert()
    alert["annotations"] = {
        "description": "x" * 513,
    }

    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(_payload([alert]))


def test_real_fastapi_alert_is_accepted() -> None:
    events = normalize_monitoring_alert_payload(
        _payload(
            [
                _alert(
                    name="RealFastAPIUnavailable",
                    severity="critical",
                    service="real-fastapi-staging",
                )
            ]
        )
    )

    assert events == (
        MonitoringAlertEvent(
            alert_name="RealFastAPIUnavailable",
            status="firing",
            severity="critical",
            service="real-fastapi-staging",
        ),
    )


@pytest.mark.parametrize(
    ("name", "severity"),
    [
        ("RealFastAPIUnavailable", "warning"),
        ("RealFastAPIHighServerErrors", "critical"),
        ("RealFastAPIHighLatency", "critical"),
    ],
)
def test_real_fastapi_mismatched_severity_is_rejected(
    name: str,
    severity: str,
) -> None:
    with pytest.raises(MonitoringAlertRequestError):
        normalize_monitoring_alert_payload(
            _payload(
                [
                    _alert(
                        name=name,
                        severity=severity,
                        service="real-fastapi-staging",
                    )
                ]
            )
        )

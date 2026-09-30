import json
from pathlib import Path

import pytest

from policy_engine import (
    Finding,
    ReportValidationError,
    Severity,
    load_gitleaks_report,
)


def _write_report(
    report_path: Path,
    payload: object,
) -> None:
    report_path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )


def test_empty_gitleaks_report_returns_no_findings(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "gitleaks-report.json"
    _write_report(report_path, [])

    assert load_gitleaks_report(report_path) == ()


def test_gitleaks_finding_is_normalized(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "gitleaks-report.json"
    _write_report(
        report_path,
        [
            {
                "Description": "Generic API key",
                "RuleID": "generic-api-key",
                "File": "sample_app/config.py",
                "StartLine": 17,
                "Secret": "redacted-example-value",
                "Match": "redacted match field",
                "Line": "redacted line field",
            }
        ],
    )

    findings = load_gitleaks_report(report_path)

    assert findings == (
        Finding(
            source="gitleaks",
            rule_id="generic-api-key",
            severity=Severity.HIGH,
            title="Generic API key",
            location="sample_app/config.py:17",
        ),
    )


def test_secret_payload_fields_are_not_retained(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "gitleaks-report.json"
    sensitive_marker = "do-not-retain-this-value"
    _write_report(
        report_path,
        [
            {
                "Description": "Test finding",
                "RuleID": "test-rule",
                "File": "example.py",
                "StartLine": 4,
                "Secret": sensitive_marker,
                "Match": sensitive_marker,
                "Line": sensitive_marker,
            }
        ],
    )

    findings = load_gitleaks_report(report_path)

    assert sensitive_marker not in repr(findings)


def test_missing_report_fails_closed(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "missing-report.json"

    with pytest.raises(
        ReportValidationError,
        match="Unable to read Gitleaks report",
    ):
        load_gitleaks_report(report_path)


def test_invalid_json_fails_closed(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "gitleaks-report.json"
    report_path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(
        ReportValidationError,
        match="Invalid JSON in Gitleaks report",
    ):
        load_gitleaks_report(report_path)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        "not-a-list",
        42,
        None,
    ],
)
def test_non_list_report_fails_closed(
    tmp_path: Path,
    payload: object,
) -> None:
    report_path = tmp_path / "gitleaks-report.json"
    _write_report(report_path, payload)

    with pytest.raises(
        ReportValidationError,
        match="Gitleaks report root must be a list",
    ):
        load_gitleaks_report(report_path)


@pytest.mark.parametrize(
    "finding",
    [
        {
            "Description": "Missing rule",
            "File": "example.py",
            "StartLine": 1,
        },
        {
            "Description": "",
            "RuleID": "test-rule",
            "File": "example.py",
            "StartLine": 1,
        },
        {
            "Description": "Invalid line",
            "RuleID": "test-rule",
            "File": "example.py",
            "StartLine": 0,
        },
    ],
)
def test_invalid_finding_fails_closed(
    tmp_path: Path,
    finding: dict[str, object],
) -> None:
    report_path = tmp_path / "gitleaks-report.json"
    _write_report(report_path, [finding])

    with pytest.raises(ReportValidationError):
        load_gitleaks_report(report_path)

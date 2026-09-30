import json
from pathlib import Path

import pytest

from policy_engine.errors import ReportValidationError
from policy_engine.models import Finding, Severity
from policy_engine.parsers.trivy import load_trivy_report


def _write_report(
    tmp_path: Path,
    payload: object,
) -> Path:
    report_path = tmp_path / "trivy-report.json"
    report_path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    return report_path


def _vulnerability(
    *,
    severity: object = "HIGH",
) -> dict[str, object]:
    return {
        "VulnerabilityID": "CVE-2026-0001",
        "PkgName": "example-package",
        "InstalledVersion": "1.0.0",
        "Severity": severity,
        "Title": "Scanner-controlled vulnerability title",
        "Description": "Scanner-controlled vulnerability description",
    }


def _misconfiguration(
    *,
    severity: object = "CRITICAL",
    status: object = "FAIL",
) -> dict[str, object]:
    return {
        "ID": "DS-0001",
        "Severity": severity,
        "Status": status,
        "Title": "Scanner-controlled misconfiguration title",
        "Description": "Scanner-controlled description",
        "Message": "Scanner-controlled source message",
        "Resolution": "Scanner-controlled resolution",
    }


def test_load_trivy_report_normalizes_supported_findings(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "ArtifactName": "example-image",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "debian:12",
                    "Vulnerabilities": [
                        _vulnerability(),
                    ],
                },
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        _misconfiguration(),
                    ],
                },
            ],
        },
    )

    findings = load_trivy_report(report_path)

    assert findings == (
        Finding(
            source="trivy-vulnerability",
            rule_id="CVE-2026-0001",
            severity=Severity.HIGH,
            title="Vulnerability in example-package 1.0.0",
            location=("debian:12:example-package@1.0.0"),
        ),
        Finding(
            source="trivy-misconfiguration",
            rule_id="DS-0001",
            severity=Severity.CRITICAL,
            title="Misconfiguration finding: DS-0001",
            location="Dockerfile",
        ),
    )


def test_load_trivy_report_does_not_propagate_scanner_text(
    tmp_path: Path,
) -> None:
    sensitive_text = "DO-NOT-PROPAGATE-THIS-TEXT"
    vulnerability = _vulnerability()
    vulnerability["Title"] = sensitive_text
    vulnerability["Description"] = sensitive_text

    misconfiguration = _misconfiguration()
    misconfiguration["Title"] = sensitive_text
    misconfiguration["Description"] = sensitive_text
    misconfiguration["Message"] = sensitive_text
    misconfiguration["Resolution"] = sensitive_text

    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Vulnerabilities": [vulnerability],
                    "Misconfigurations": [misconfiguration],
                }
            ],
        },
    )

    findings = load_trivy_report(report_path)
    serialized_findings = repr(findings)

    assert sensitive_text not in serialized_findings


@pytest.mark.parametrize(
    ("raw_severity", "expected_severity"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("INFO", Severity.INFO),
        ("high", Severity.HIGH),
        ("FUTURE-SEVERITY", Severity.UNKNOWN),
    ],
)
def test_load_trivy_report_maps_vulnerability_severity(
    tmp_path: Path,
    raw_severity: str,
    expected_severity: Severity,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        _vulnerability(
                            severity=raw_severity,
                        )
                    ],
                }
            ],
        },
    )

    findings = load_trivy_report(report_path)

    assert findings[0].severity is expected_severity


@pytest.mark.parametrize(
    ("raw_severity", "expected_severity"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("INFO", Severity.INFO),
        ("warning", Severity.UNKNOWN),
    ],
)
def test_load_trivy_report_maps_misconfiguration_severity(
    tmp_path: Path,
    raw_severity: str,
    expected_severity: Severity,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        _misconfiguration(
                            severity=raw_severity,
                        )
                    ],
                }
            ],
        },
    )

    findings = load_trivy_report(report_path)

    assert findings[0].severity is expected_severity


@pytest.mark.parametrize(
    "status",
    [
        "PASS",
        "EXCEPTION",
        "pass",
        "exception",
    ],
)
def test_load_trivy_report_omits_non_failing_misconfigurations(
    tmp_path: Path,
    status: str,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        _misconfiguration(status=status),
                    ],
                }
            ],
        },
    )

    assert load_trivy_report(report_path) == ()


def test_load_trivy_report_accepts_omitted_results(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "ArtifactName": ".",
            "ArtifactType": "filesystem",
        },
    )

    assert load_trivy_report(report_path) == ()


def test_load_trivy_report_accepts_empty_results(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [],
        },
    )

    assert load_trivy_report(report_path) == ()


def test_load_trivy_report_rejects_missing_file(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "missing.json"

    with pytest.raises(
        ReportValidationError,
        match="Unable to read Trivy report",
    ):
        load_trivy_report(report_path)


def test_load_trivy_report_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "trivy-report.json"
    report_path.write_text(
        "{not-json",
        encoding="utf-8",
    )

    with pytest.raises(
        ReportValidationError,
        match="Invalid JSON in Trivy report",
    ):
        load_trivy_report(report_path)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "report",
        1,
        None,
    ],
)
def test_load_trivy_report_rejects_non_object_root(
    tmp_path: Path,
    payload: object,
) -> None:
    report_path = _write_report(
        tmp_path,
        payload,
    )

    with pytest.raises(
        ReportValidationError,
        match="root must be an object",
    ):
        load_trivy_report(report_path)


@pytest.mark.parametrize(
    "schema_version",
    [
        None,
        True,
        1,
        3,
        "2",
    ],
)
def test_load_trivy_report_rejects_unsupported_schema(
    tmp_path: Path,
    schema_version: object,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": schema_version,
            "Results": [],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match="unsupported SchemaVersion",
    ):
        load_trivy_report(report_path)


@pytest.mark.parametrize(
    "results",
    [
        None,
        {},
        "results",
        1,
    ],
)
def test_load_trivy_report_rejects_invalid_results(
    tmp_path: Path,
    results: object,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": results,
        },
    )

    with pytest.raises(
        ReportValidationError,
        match="invalid Results",
    ):
        load_trivy_report(report_path)


def test_load_trivy_report_rejects_non_object_result(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": ["invalid"],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match="result 0 must be an object",
    ):
        load_trivy_report(report_path)


@pytest.mark.parametrize(
    "target",
    [
        None,
        "",
        "   ",
        [],
    ],
)
def test_load_trivy_report_rejects_invalid_target(
    tmp_path: Path,
    target: object,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": target,
                }
            ],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match="invalid Target",
    ):
        load_trivy_report(report_path)


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("Vulnerabilities", None),
        ("Vulnerabilities", {}),
        ("Misconfigurations", None),
        ("Misconfigurations", {}),
    ],
)
def test_load_trivy_report_rejects_invalid_finding_collection(
    tmp_path: Path,
    field_name: str,
    invalid_value: object,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "Dockerfile",
                    field_name: invalid_value,
                }
            ],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match=f"invalid {field_name}",
    ):
        load_trivy_report(report_path)


def test_load_trivy_report_rejects_non_object_vulnerability(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "debian:12",
                    "Vulnerabilities": ["invalid"],
                }
            ],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match="vulnerability 0 must be an object",
    ):
        load_trivy_report(report_path)


@pytest.mark.parametrize(
    "field_name",
    [
        "VulnerabilityID",
        "PkgName",
        "InstalledVersion",
        "Severity",
    ],
)
def test_load_trivy_report_rejects_incomplete_vulnerability(
    tmp_path: Path,
    field_name: str,
) -> None:
    vulnerability = _vulnerability()
    vulnerability.pop(field_name)

    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "debian:12",
                    "Vulnerabilities": [vulnerability],
                }
            ],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match=f"invalid {field_name}",
    ):
        load_trivy_report(report_path)


def test_load_trivy_report_rejects_non_object_misconfiguration(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": ["invalid"],
                }
            ],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match="misconfiguration 0 must be an object",
    ):
        load_trivy_report(report_path)


@pytest.mark.parametrize(
    "field_name",
    [
        "ID",
        "Severity",
        "Status",
    ],
)
def test_load_trivy_report_rejects_incomplete_misconfiguration(
    tmp_path: Path,
    field_name: str,
) -> None:
    misconfiguration = _misconfiguration()
    misconfiguration.pop(field_name)

    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        misconfiguration,
                    ],
                }
            ],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match=f"invalid {field_name}",
    ):
        load_trivy_report(report_path)


def test_load_trivy_report_rejects_unknown_status(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        _misconfiguration(
                            status="UNKNOWN-STATUS",
                        )
                    ],
                }
            ],
        },
    )

    with pytest.raises(
        ReportValidationError,
        match="invalid Status",
    ):
        load_trivy_report(report_path)

import json
from pathlib import Path

import pytest

from policy_engine import (
    GateDecision,
    ReportValidationError,
    evaluate_findings,
)
from policy_engine.models import Severity
from policy_engine.parsers.pip_audit import (
    load_pip_audit_report,
)


def _write_report(
    tmp_path: Path,
    payload: object,
) -> Path:
    report_path = tmp_path / "pip-audit-report.json"
    normalized_payload = (
        {
            "dependencies": payload,
            "fixes": [],
        }
        if isinstance(payload, list)
        else payload
    )
    report_path.write_text(
        json.dumps(normalized_payload),
        encoding="utf-8",
    )
    return report_path


def test_empty_report_returns_no_findings(
    tmp_path: Path,
) -> None:
    report_path = _write_report(tmp_path, [])

    assert load_pip_audit_report(report_path) == ()


def test_dependency_without_vulnerabilities_returns_no_findings(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        [
            {
                "name": "fastapi",
                "version": "0.141.1",
                "vulns": [],
            }
        ],
    )

    assert load_pip_audit_report(report_path) == ()


def test_vulnerability_is_normalized(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        [
            {
                "name": "example-package",
                "version": "1.2.3",
                "vulns": [
                    {
                        "id": "PYSEC-2026-001",
                        "fix_versions": ["1.2.4"],
                        "aliases": ["CVE-2026-0001"],
                        "description": "Untrusted advisory text",
                    }
                ],
            }
        ],
    )

    findings = load_pip_audit_report(report_path)

    assert len(findings) == 1

    finding = findings[0]
    assert finding.source == "pip-audit"
    assert finding.rule_id == "PYSEC-2026-001"
    assert finding.severity is Severity.UNKNOWN
    assert finding.title == ("Known vulnerability in example-package 1.2.3")
    assert finding.location == "example-package==1.2.3"
    assert "Untrusted advisory text" not in finding.title


def test_finding_order_is_preserved(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        [
            {
                "name": "first-package",
                "version": "1.0",
                "vulns": [
                    {"id": "PYSEC-001"},
                    {"id": "PYSEC-002"},
                ],
            },
            {
                "name": "second-package",
                "version": "2.0",
                "vulns": [
                    {"id": "PYSEC-003"},
                ],
            },
        ],
    )

    findings = load_pip_audit_report(report_path)

    assert [finding.rule_id for finding in findings] == [
        "PYSEC-001",
        "PYSEC-002",
        "PYSEC-003",
    ]


def test_unknown_severity_blocks_default_policy(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        [
            {
                "name": "example-package",
                "version": "1.2.3",
                "vulns": [{"id": "PYSEC-2026-001"}],
            }
        ],
    )

    result = evaluate_findings(load_pip_audit_report(report_path))

    assert result.decision is GateDecision.BLOCK


def test_missing_report_fails_closed(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "missing.json"

    with pytest.raises(
        ReportValidationError,
        match="Unable to read pip-audit report",
    ):
        load_pip_audit_report(report_path)


def test_invalid_json_fails_closed(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "pip-audit-report.json"
    report_path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(
        ReportValidationError,
        match="Invalid JSON in pip-audit report",
    ):
        load_pip_audit_report(report_path)


@pytest.mark.parametrize(
    "payload",
    [{}, "invalid", 42, None],
)
def test_invalid_root_fails_closed(
    tmp_path: Path,
    payload: object,
) -> None:
    report_path = _write_report(tmp_path, payload)

    with pytest.raises(
        ReportValidationError,
        match="pip-audit report root",
    ):
        load_pip_audit_report(report_path)


@pytest.mark.parametrize(
    "dependency",
    [None, "invalid", []],
)
def test_non_object_dependency_fails_closed(
    tmp_path: Path,
    dependency: object,
) -> None:
    report_path = _write_report(tmp_path, [dependency])

    with pytest.raises(
        ReportValidationError,
        match="dependency 0 must be an object",
    ):
        load_pip_audit_report(report_path)


@pytest.mark.parametrize(
    ("dependency", "expected_message"),
    [
        (
            {
                "version": "1.0",
                "vulns": [],
            },
            "invalid name",
        ),
        (
            {
                "name": "example-package",
                "version": "",
                "vulns": [],
            },
            "invalid version",
        ),
        (
            {
                "name": "example-package",
                "version": "1.0",
                "vulns": {},
            },
            "invalid vulns",
        ),
    ],
)
def test_invalid_dependency_fields_fail_closed(
    tmp_path: Path,
    dependency: object,
    expected_message: str,
) -> None:
    report_path = _write_report(tmp_path, [dependency])

    with pytest.raises(
        ReportValidationError,
        match=expected_message,
    ):
        load_pip_audit_report(report_path)


@pytest.mark.parametrize(
    ("vulnerability", "expected_message"),
    [
        (None, "must be an object"),
        ({}, "invalid id"),
        ({"id": " "}, "invalid id"),
    ],
)
def test_invalid_vulnerability_fails_closed(
    tmp_path: Path,
    vulnerability: object,
    expected_message: str,
) -> None:
    report_path = _write_report(
        tmp_path,
        [
            {
                "name": "example-package",
                "version": "1.0",
                "vulns": [vulnerability],
            }
        ],
    )

    with pytest.raises(
        ReportValidationError,
        match=expected_message,
    ):
        load_pip_audit_report(report_path)


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        (
            {
                "dependencies": [],
                "fixes": [],
                "unexpected": True,
            },
            "missing or unsupported keys",
        ),
        (
            {
                "dependencies": {},
                "fixes": [],
            },
            "invalid dependencies",
        ),
        (
            {
                "dependencies": [],
                "fixes": {},
            },
            "invalid fixes",
        ),
    ],
)
def test_invalid_report_structure_fails_closed(
    tmp_path: Path,
    payload: object,
    expected_message: str,
) -> None:
    report_path = _write_report(tmp_path, payload)

    with pytest.raises(
        ReportValidationError,
        match=expected_message,
    ):
        load_pip_audit_report(report_path)

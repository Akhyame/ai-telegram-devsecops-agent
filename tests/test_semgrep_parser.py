import json
from pathlib import Path

import pytest

from policy_engine import (
    GateDecision,
    ReportValidationError,
    evaluate_findings,
)
from policy_engine.models import Severity
from policy_engine.parsers.semgrep import load_semgrep_report


def _write_report(
    tmp_path: Path,
    payload: object,
) -> Path:
    report_path = tmp_path / "semgrep-report.json"
    report_path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    return report_path


def _report(
    *,
    results: object | None = None,
    errors: object | None = None,
    paths: object | None = None,
) -> dict[str, object]:
    return {
        "version": "1.174.0",
        "results": [] if results is None else results,
        "errors": [] if errors is None else errors,
        "paths": ({"scanned": ["sample_app/main.py"]} if paths is None else paths),
    }


def _result(
    *,
    check_id: object = "python.security.example-rule",
    file_path: object = "sample_app/main.py",
    start: object = None,
    extra: object = None,
) -> dict[str, object]:
    if start is None:
        start = {
            "line": 12,
            "col": 5,
            "offset": 200,
        }

    if extra is None:
        extra = {
            "message": "Matched source value: sensitive_value",
            "metadata": {},
            "severity": "ERROR",
            "fingerprint": "test-fingerprint",
            "lines": "dangerous_call(sensitive_value)",
            "is_ignored": False,
        }

    return {
        "check_id": check_id,
        "path": file_path,
        "start": start,
        "end": {
            "line": 12,
            "col": 30,
            "offset": 225,
        },
        "extra": extra,
    }


def test_empty_report_returns_no_findings(
    tmp_path: Path,
) -> None:
    report_path = _write_report(tmp_path, _report())

    assert load_semgrep_report(report_path) == ()


@pytest.mark.parametrize(
    ("semgrep_severity", "expected_severity"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("ERROR", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("WARNING", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("INFO", Severity.INFO),
    ],
)
def test_severity_is_normalized(
    tmp_path: Path,
    semgrep_severity: str,
    expected_severity: Severity,
) -> None:
    result = _result(
        extra={
            "message": "Example finding",
            "severity": semgrep_severity,
            "is_ignored": False,
        }
    )
    report_path = _write_report(
        tmp_path,
        _report(results=[result]),
    )

    findings = load_semgrep_report(report_path)

    assert len(findings) == 1
    assert findings[0].severity is expected_severity


def test_finding_uses_controlled_fields(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        _report(results=[_result()]),
    )

    findings = load_semgrep_report(report_path)

    assert len(findings) == 1

    finding = findings[0]
    assert finding.source == "semgrep"
    assert finding.rule_id == "python.security.example-rule"
    assert finding.severity is Severity.HIGH
    assert finding.title == ("Static analysis finding: python.security.example-rule")
    assert finding.location == "sample_app/main.py:12"
    assert "sensitive_value" not in finding.title
    assert "dangerous_call" not in finding.title


def test_unknown_severity_fails_closed(
    tmp_path: Path,
) -> None:
    result = _result(
        extra={
            "message": "Future severity",
            "severity": "FUTURE_LEVEL",
            "is_ignored": False,
        }
    )
    report_path = _write_report(
        tmp_path,
        _report(results=[result]),
    )

    findings = load_semgrep_report(report_path)
    evaluation = evaluate_findings(findings)

    assert findings[0].severity is Severity.UNKNOWN
    assert evaluation.decision is GateDecision.BLOCK


def test_ignored_finding_is_not_returned(
    tmp_path: Path,
) -> None:
    result = _result(
        extra={
            "message": "Ignored finding",
            "severity": "ERROR",
            "is_ignored": True,
        }
    )
    report_path = _write_report(
        tmp_path,
        _report(results=[result]),
    )

    assert load_semgrep_report(report_path) == ()


def test_finding_order_is_preserved(
    tmp_path: Path,
) -> None:
    results = [
        _result(check_id="rule.first"),
        _result(check_id="rule.second"),
        _result(check_id="rule.third"),
    ]
    report_path = _write_report(
        tmp_path,
        _report(results=results),
    )

    findings = load_semgrep_report(report_path)

    assert [finding.rule_id for finding in findings] == [
        "rule.first",
        "rule.second",
        "rule.third",
    ]


def test_scan_errors_fail_closed(
    tmp_path: Path,
) -> None:
    report_path = _write_report(
        tmp_path,
        _report(
            errors=[
                {
                    "type": "SemgrepError",
                    "message": "scan failed",
                }
            ]
        ),
    )

    with pytest.raises(
        ReportValidationError,
        match="contains scan errors",
    ):
        load_semgrep_report(report_path)


def test_missing_report_fails_closed(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "missing.json"

    with pytest.raises(
        ReportValidationError,
        match="Unable to read Semgrep report",
    ):
        load_semgrep_report(report_path)


def test_invalid_json_fails_closed(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "semgrep-report.json"
    report_path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(
        ReportValidationError,
        match="Invalid JSON in Semgrep report",
    ):
        load_semgrep_report(report_path)


@pytest.mark.parametrize(
    "payload",
    [[], "invalid", 42, None],
)
def test_non_object_root_fails_closed(
    tmp_path: Path,
    payload: object,
) -> None:
    report_path = _write_report(tmp_path, payload)

    with pytest.raises(
        ReportValidationError,
        match="report root must be an object",
    ):
        load_semgrep_report(report_path)


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        (
            {
                "errors": [],
                "results": {},
                "paths": {"scanned": []},
            },
            "invalid results",
        ),
        (
            {
                "errors": {},
                "results": [],
                "paths": {"scanned": []},
            },
            "invalid errors",
        ),
        (
            {
                "errors": [],
                "results": [],
                "paths": [],
            },
            "invalid paths",
        ),
        (
            {
                "errors": [],
                "results": [],
                "paths": {"scanned": {}},
            },
            "invalid scanned paths",
        ),
    ],
)
def test_invalid_report_fields_fail_closed(
    tmp_path: Path,
    payload: object,
    expected_message: str,
) -> None:
    report_path = _write_report(tmp_path, payload)

    with pytest.raises(
        ReportValidationError,
        match=expected_message,
    ):
        load_semgrep_report(report_path)


@pytest.mark.parametrize(
    "result",
    [None, "invalid", []],
)
def test_non_object_result_fails_closed(
    tmp_path: Path,
    result: object,
) -> None:
    report_path = _write_report(
        tmp_path,
        _report(results=[result]),
    )

    with pytest.raises(
        ReportValidationError,
        match="result 0 must be an object",
    ):
        load_semgrep_report(report_path)


@pytest.mark.parametrize(
    ("result", "expected_message"),
    [
        (
            _result(check_id=""),
            "invalid check_id",
        ),
        (
            _result(file_path=""),
            "invalid path",
        ),
        (
            _result(start=[]),
            "invalid start",
        ),
        (
            _result(start={"line": 0}),
            "invalid start line",
        ),
        (
            _result(start={"line": True}),
            "invalid start line",
        ),
        (
            _result(extra=[]),
            "invalid extra",
        ),
        (
            _result(
                extra={
                    "message": None,
                    "severity": "ERROR",
                }
            ),
            "invalid message",
        ),
        (
            _result(
                extra={
                    "message": "Example",
                    "severity": None,
                }
            ),
            "invalid severity",
        ),
        (
            _result(
                extra={
                    "message": "Example",
                    "severity": "ERROR",
                    "is_ignored": "false",
                }
            ),
            "invalid is_ignored",
        ),
    ],
)
def test_invalid_result_fields_fail_closed(
    tmp_path: Path,
    result: object,
    expected_message: str,
) -> None:
    report_path = _write_report(
        tmp_path,
        _report(results=[result]),
    )

    with pytest.raises(
        ReportValidationError,
        match=expected_message,
    ):
        load_semgrep_report(report_path)

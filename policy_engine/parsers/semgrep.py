import json
from pathlib import Path

from policy_engine.errors import ReportValidationError
from policy_engine.models import Finding, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "ERROR": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "WARNING": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def load_semgrep_report(
    report_path: str | Path,
) -> tuple[Finding, ...]:
    path = Path(report_path)

    try:
        raw_report = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportValidationError(f"Unable to read Semgrep report: {path.name}") from exc

    try:
        payload: object = json.loads(raw_report)
    except json.JSONDecodeError as exc:
        raise ReportValidationError(f"Invalid JSON in Semgrep report: {path.name}") from exc

    if not isinstance(payload, dict):
        raise ReportValidationError("Semgrep report root must be an object")

    errors = payload.get("errors")
    if not isinstance(errors, list):
        raise ReportValidationError("Semgrep report has invalid errors")

    if errors:
        raise ReportValidationError("Semgrep report contains scan errors")

    results = payload.get("results")
    if not isinstance(results, list):
        raise ReportValidationError("Semgrep report has invalid results")

    paths = payload.get("paths")
    if not isinstance(paths, dict):
        raise ReportValidationError("Semgrep report has invalid paths")

    scanned_paths = paths.get("scanned")
    if not isinstance(scanned_paths, list):
        raise ReportValidationError("Semgrep report has invalid scanned paths")

    findings: list[Finding] = []

    for result_index, result in enumerate(results):
        finding = _normalize_result(result, result_index)

        if finding is not None:
            findings.append(finding)

    return tuple(findings)


def _normalize_result(
    result: object,
    result_index: int,
) -> Finding | None:
    if not isinstance(result, dict):
        raise ReportValidationError(f"Semgrep result {result_index} must be an object")

    check_id = _required_text(
        result,
        "check_id",
        result_index,
    )
    file_path = _required_text(
        result,
        "path",
        result_index,
    )

    start = result.get("start")
    if not isinstance(start, dict):
        raise ReportValidationError(f"Semgrep result {result_index} has invalid start")

    start_line = start.get("line")
    if not isinstance(start_line, int) or isinstance(start_line, bool) or start_line < 1:
        raise ReportValidationError(f"Semgrep result {result_index} has invalid start line")

    extra = result.get("extra")
    if not isinstance(extra, dict):
        raise ReportValidationError(f"Semgrep result {result_index} has invalid extra")

    message = extra.get("message")
    if not isinstance(message, str):
        raise ReportValidationError(f"Semgrep result {result_index} has invalid message")

    severity_value = extra.get("severity")
    if not isinstance(severity_value, str):
        raise ReportValidationError(f"Semgrep result {result_index} has invalid severity")

    is_ignored = extra.get("is_ignored", False)
    if not isinstance(is_ignored, bool):
        raise ReportValidationError(f"Semgrep result {result_index} has invalid is_ignored")

    if is_ignored:
        return None

    severity = _SEVERITY_MAP.get(
        severity_value.upper(),
        Severity.UNKNOWN,
    )

    return Finding(
        source="semgrep",
        rule_id=check_id,
        severity=severity,
        title=f"Static analysis finding: {check_id}",
        location=f"{file_path}:{start_line}",
    )


def _required_text(
    result: dict[object, object],
    field_name: str,
    result_index: int,
) -> str:
    value = result.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ReportValidationError(f"Semgrep result {result_index} has invalid {field_name}")

    return value.strip()

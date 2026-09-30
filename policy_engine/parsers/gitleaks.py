import json
from pathlib import Path

from policy_engine.errors import ReportValidationError
from policy_engine.models import Finding, Severity


def load_gitleaks_report(
    report_path: str | Path,
) -> tuple[Finding, ...]:
    path = Path(report_path)

    try:
        raw_report = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportValidationError(f"Unable to read Gitleaks report: {path.name}") from exc

    try:
        payload: object = json.loads(raw_report)
    except json.JSONDecodeError as exc:
        raise ReportValidationError(f"Invalid JSON in Gitleaks report: {path.name}") from exc

    if not isinstance(payload, list):
        raise ReportValidationError("Gitleaks report root must be a list")

    return tuple(_normalize_finding(item, index) for index, item in enumerate(payload))


def _normalize_finding(
    item: object,
    index: int,
) -> Finding:
    if not isinstance(item, dict):
        raise ReportValidationError(f"Gitleaks finding {index} must be an object")

    rule_id = _required_text(item, "RuleID", index)
    description = _required_text(item, "Description", index)
    file_path = _required_text(item, "File", index)

    start_line = item.get("StartLine")
    if not isinstance(start_line, int) or isinstance(start_line, bool) or start_line < 1:
        raise ReportValidationError(f"Gitleaks finding {index} has invalid StartLine")

    return Finding(
        source="gitleaks",
        rule_id=rule_id,
        severity=Severity.HIGH,
        title=description,
        location=f"{file_path}:{start_line}",
    )


def _required_text(
    item: dict[object, object],
    field_name: str,
    index: int,
) -> str:
    value = item.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ReportValidationError(f"Gitleaks finding {index} has invalid {field_name}")

    return value.strip()

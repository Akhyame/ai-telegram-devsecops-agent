import json
from pathlib import Path

from policy_engine.errors import ReportValidationError
from policy_engine.models import Finding, Severity


def load_pip_audit_report(
    report_path: str | Path,
) -> tuple[Finding, ...]:
    path = Path(report_path)

    try:
        raw_report = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportValidationError(f"Unable to read pip-audit report: {path.name}") from exc

    try:
        payload: object = json.loads(raw_report)
    except json.JSONDecodeError as exc:
        raise ReportValidationError(f"Invalid JSON in pip-audit report: {path.name}") from exc

    if not isinstance(payload, dict):
        raise ReportValidationError("pip-audit report root must be an object")

    if set(payload) != {"dependencies", "fixes"}:
        raise ReportValidationError("pip-audit report root has missing or unsupported keys")

    dependencies = payload["dependencies"]
    if not isinstance(dependencies, list):
        raise ReportValidationError("pip-audit report has invalid dependencies")

    fixes = payload["fixes"]
    if not isinstance(fixes, list):
        raise ReportValidationError("pip-audit report has invalid fixes")

    findings: list[Finding] = []

    for dependency_index, dependency in enumerate(dependencies):
        findings.extend(_normalize_dependency(dependency, dependency_index))

    return tuple(findings)


def _normalize_dependency(
    dependency: object,
    dependency_index: int,
) -> tuple[Finding, ...]:
    if not isinstance(dependency, dict):
        raise ReportValidationError(f"pip-audit dependency {dependency_index} must be an object")

    name = _required_text(
        dependency,
        "name",
        dependency_index,
    )
    version = _required_text(
        dependency,
        "version",
        dependency_index,
    )

    vulnerabilities = dependency.get("vulns")
    if not isinstance(vulnerabilities, list):
        raise ReportValidationError(f"pip-audit dependency {dependency_index} has invalid vulns")

    return tuple(
        _normalize_vulnerability(
            vulnerability,
            dependency_index,
            vulnerability_index,
            name,
            version,
        )
        for vulnerability_index, vulnerability in enumerate(vulnerabilities)
    )


def _normalize_vulnerability(
    vulnerability: object,
    dependency_index: int,
    vulnerability_index: int,
    package_name: str,
    package_version: str,
) -> Finding:
    if not isinstance(vulnerability, dict):
        raise ReportValidationError(
            f"pip-audit vulnerability {dependency_index}:{vulnerability_index} must be an object"
        )

    vulnerability_id = vulnerability.get("id")
    if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
        raise ReportValidationError(
            f"pip-audit vulnerability {dependency_index}:{vulnerability_index} has invalid id"
        )

    return Finding(
        source="pip-audit",
        rule_id=vulnerability_id.strip(),
        severity=Severity.UNKNOWN,
        title=(f"Known vulnerability in {package_name} {package_version}"),
        location=f"{package_name}=={package_version}",
    )


def _required_text(
    dependency: dict[object, object],
    field_name: str,
    dependency_index: int,
) -> str:
    value = dependency.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ReportValidationError(
            f"pip-audit dependency {dependency_index} has invalid {field_name}"
        )

    return value.strip()

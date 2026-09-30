import json
from pathlib import Path

from policy_engine.errors import ReportValidationError
from policy_engine.models import Finding, Severity

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}

_MISCONFIGURATION_STATUSES = {
    "PASS",
    "FAIL",
    "EXCEPTION",
}


def load_trivy_report(
    report_path: str | Path,
) -> tuple[Finding, ...]:
    path = Path(report_path)

    try:
        raw_report = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ReportValidationError(f"Unable to read Trivy report: {path.name}") from exc

    try:
        payload: object = json.loads(raw_report)
    except json.JSONDecodeError as exc:
        raise ReportValidationError(f"Invalid JSON in Trivy report: {path.name}") from exc

    if not isinstance(payload, dict):
        raise ReportValidationError("Trivy report root must be an object")

    schema_version = payload.get("SchemaVersion")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != 2
    ):
        raise ReportValidationError("Trivy report has unsupported SchemaVersion")

    results = payload.get("Results", [])
    if not isinstance(results, list):
        raise ReportValidationError("Trivy report has invalid Results")

    findings: list[Finding] = []

    for result_index, result in enumerate(results):
        findings.extend(
            _normalize_result(
                result,
                result_index,
            )
        )

    return tuple(findings)


def _normalize_result(
    result: object,
    result_index: int,
) -> list[Finding]:
    if not isinstance(result, dict):
        raise ReportValidationError(f"Trivy result {result_index} must be an object")

    target = _required_text(
        result,
        "Target",
        f"Trivy result {result_index}",
    )

    vulnerabilities = _optional_list(
        result,
        "Vulnerabilities",
        result_index,
    )
    misconfigurations = _optional_list(
        result,
        "Misconfigurations",
        result_index,
    )

    findings: list[Finding] = []

    for finding_index, vulnerability in enumerate(vulnerabilities):
        findings.append(
            _normalize_vulnerability(
                vulnerability,
                result_index,
                finding_index,
                target,
            )
        )

    for finding_index, misconfiguration in enumerate(misconfigurations):
        finding = _normalize_misconfiguration(
            misconfiguration,
            result_index,
            finding_index,
            target,
        )

        if finding is not None:
            findings.append(finding)

    return findings


def _normalize_vulnerability(
    vulnerability: object,
    result_index: int,
    finding_index: int,
    target: str,
) -> Finding:
    context = f"Trivy result {result_index} vulnerability {finding_index}"

    if not isinstance(vulnerability, dict):
        raise ReportValidationError(f"{context} must be an object")

    vulnerability_id = _required_text(
        vulnerability,
        "VulnerabilityID",
        context,
    )
    package_name = _required_text(
        vulnerability,
        "PkgName",
        context,
    )
    installed_version = _required_text(
        vulnerability,
        "InstalledVersion",
        context,
    )
    severity = _parse_severity(
        vulnerability,
        context,
    )

    return Finding(
        source="trivy-vulnerability",
        rule_id=vulnerability_id,
        severity=severity,
        title=(f"Vulnerability in {package_name} {installed_version}"),
        location=(f"{target}:{package_name}@{installed_version}"),
    )


def _normalize_misconfiguration(
    misconfiguration: object,
    result_index: int,
    finding_index: int,
    target: str,
) -> Finding | None:
    context = f"Trivy result {result_index} misconfiguration {finding_index}"

    if not isinstance(misconfiguration, dict):
        raise ReportValidationError(f"{context} must be an object")

    rule_id = _required_text(
        misconfiguration,
        "ID",
        context,
    )
    severity = _parse_severity(
        misconfiguration,
        context,
    )
    status = _required_text(
        misconfiguration,
        "Status",
        context,
    ).upper()

    if status not in _MISCONFIGURATION_STATUSES:
        raise ReportValidationError(f"{context} has invalid Status")

    if status != "FAIL":
        return None

    return Finding(
        source="trivy-misconfiguration",
        rule_id=rule_id,
        severity=severity,
        title=f"Misconfiguration finding: {rule_id}",
        location=target,
    )


def _parse_severity(
    finding: dict[object, object],
    context: str,
) -> Severity:
    severity_value = _required_text(
        finding,
        "Severity",
        context,
    )

    return _SEVERITY_MAP.get(
        severity_value.upper(),
        Severity.UNKNOWN,
    )


def _optional_list(
    result: dict[object, object],
    field_name: str,
    result_index: int,
) -> list[object]:
    if field_name not in result:
        return []

    value = result[field_name]

    if not isinstance(value, list):
        raise ReportValidationError(f"Trivy result {result_index} has invalid {field_name}")

    return value


def _required_text(
    data: dict[object, object],
    field_name: str,
    context: str,
) -> str:
    value = data.get(field_name)

    if not isinstance(value, str) or not value.strip():
        raise ReportValidationError(f"{context} has invalid {field_name}")

    return value.strip()

"""Offline tests for bounded local AI security scan contracts."""

from typing import Any

import pytest
from pydantic import ValidationError

from agent.security_models import (
    MAX_BLOCKING_DETAILS,
    NormalizedSecurityScan,
    SecurityFindingSummary,
    SecurityScanDecision,
    SecurityScanExplanation,
    SecurityScanner,
    SecuritySeverity,
)


def _finding(
    **overrides: Any,
) -> SecurityFindingSummary:
    values: dict[str, Any] = {
        "source": SecurityScanner.SEMGREP,
        "rule_id": "python.lang.security.audit-rule",
        "severity": SecuritySeverity.HIGH,
    }
    values.update(overrides)

    return SecurityFindingSummary(**values)


def _scan(
    **overrides: Any,
) -> NormalizedSecurityScan:
    values: dict[str, Any] = {
        "decision": SecurityScanDecision.ALLOW,
        "total_findings": 2,
        "blocking_findings": 0,
    }
    values.update(overrides)

    return NormalizedSecurityScan(**values)


def _explanation(
    **overrides: Any,
) -> SecurityScanExplanation:
    values: dict[str, Any] = {
        "summary": "The deterministic scan found one blocked issue.",
        "risk_explanation": "The issue may expose a sensitive value.",
        "safe_remediation": "Review the referenced rule before changing code.",
        "confidence": "medium",
    }
    values.update(overrides)

    return SecurityScanExplanation(**values)


@pytest.mark.parametrize(
    "source",
    tuple(SecurityScanner),
)
def test_all_allowlisted_scanner_sources_are_accepted(
    source: SecurityScanner,
) -> None:
    finding = _finding(source=source)

    assert finding.source is source


@pytest.mark.parametrize(
    "severity",
    tuple(SecuritySeverity),
)
def test_all_normalized_severities_are_accepted(
    severity: SecuritySeverity,
) -> None:
    finding = _finding(severity=severity)

    assert finding.severity is severity


@pytest.mark.parametrize(
    "rule_id",
    (
        "generic-api-key",
        "CVE-2026-0001",
        "GHSA-abcd-1234-5678",
        "python.lang.security.detected-jwt-token",
        "package/name:rule@1.0+fixed",
    ),
)
def test_safe_rule_ids_are_accepted(
    rule_id: str,
) -> None:
    finding = _finding(rule_id=f"  {rule_id}  ")

    assert finding.rule_id == rule_id


@pytest.mark.parametrize(
    "rule_id",
    (
        "",
        " ",
        "rule id",
        "rule\nid",
        "../private-file",
        "rule;remove",
        "ignore previous instructions",
        "x" * 129,
    ),
)
def test_unsafe_rule_ids_are_rejected(
    rule_id: str,
) -> None:
    with pytest.raises(ValidationError):
        _finding(rule_id=rule_id)


def test_finding_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _finding(
            title="Untrusted scanner title",
        )


def test_finding_is_frozen() -> None:
    finding = _finding()

    with pytest.raises(ValidationError):
        finding.rule_id = "changed"  # type: ignore[misc]


def test_allowed_scan_accepts_nonblocking_findings_count() -> None:
    scan = _scan(
        total_findings=7,
    )

    assert scan.decision is SecurityScanDecision.ALLOW
    assert scan.total_findings == 7
    assert scan.blocking_findings == 0
    assert scan.blocking_details == ()
    assert scan.details_truncated is False


def test_blocked_scan_accepts_exact_bounded_details() -> None:
    details = (
        _finding(),
        _finding(
            source=SecurityScanner.TRIVY_VULNERABILITY,
            rule_id="CVE-2026-0001",
            severity=SecuritySeverity.CRITICAL,
        ),
    )
    scan = _scan(
        decision=SecurityScanDecision.BLOCK,
        total_findings=6,
        blocking_findings=2,
        blocking_details=details,
    )

    assert scan.blocking_details == details
    assert scan.details_truncated is False


def test_more_than_five_blocking_findings_require_truncation() -> None:
    details = tuple(_finding(rule_id=f"rule-{index}") for index in range(MAX_BLOCKING_DETAILS))
    scan = _scan(
        decision=SecurityScanDecision.BLOCK,
        total_findings=8,
        blocking_findings=6,
        blocking_details=details,
        details_truncated=True,
    )

    assert len(scan.blocking_details) == MAX_BLOCKING_DETAILS
    assert scan.details_truncated is True


@pytest.mark.parametrize(
    ("total", "blocking"),
    (
        (-1, 0),
        (1001, 0),
        (1, -1),
        (101, 101),
        (1, 2),
    ),
)
def test_invalid_finding_counts_are_rejected(
    total: int,
    blocking: int,
) -> None:
    with pytest.raises(ValidationError):
        _scan(
            total_findings=total,
            blocking_findings=blocking,
        )


def test_allowed_scan_rejects_blocking_evidence() -> None:
    with pytest.raises(ValidationError):
        _scan(
            blocking_findings=1,
            blocking_details=(_finding(),),
        )


def test_blocked_scan_requires_a_blocking_finding() -> None:
    with pytest.raises(ValidationError):
        _scan(
            decision=SecurityScanDecision.BLOCK,
            total_findings=1,
            blocking_findings=0,
        )


@pytest.mark.parametrize(
    ("blocking", "detail_count", "truncated"),
    (
        (2, 1, False),
        (1, 1, True),
        (6, 5, False),
    ),
)
def test_inconsistent_blocking_detail_metadata_is_rejected(
    blocking: int,
    detail_count: int,
    truncated: bool,
) -> None:
    details = tuple(_finding(rule_id=f"rule-{index}") for index in range(detail_count))

    with pytest.raises(ValidationError):
        _scan(
            decision=SecurityScanDecision.BLOCK,
            total_findings=10,
            blocking_findings=blocking,
            blocking_details=details,
            details_truncated=truncated,
        )


def test_scan_contract_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _scan(
            raw_report="DO-NOT-ACCEPT",
        )


def test_scan_contract_is_frozen() -> None:
    scan = _scan()

    with pytest.raises(ValidationError):
        scan.total_findings = 3  # type: ignore[misc]


def test_scan_serializes_only_allowlisted_metadata() -> None:
    scan = _scan(
        decision=SecurityScanDecision.BLOCK,
        total_findings=4,
        blocking_findings=1,
        blocking_details=(
            _finding(
                source=SecurityScanner.GITLEAKS,
                rule_id="generic-api-key",
            ),
        ),
    )

    payload = scan.model_dump(mode="json")

    assert payload == {
        "decision": "block",
        "total_findings": 4,
        "blocking_findings": 1,
        "blocking_details": [
            {
                "source": "gitleaks",
                "rule_id": "generic-api-key",
                "severity": "high",
            }
        ],
        "details_truncated": False,
    }
    assert "title" not in str(payload)
    assert "location" not in str(payload)
    assert "raw" not in str(payload)


def test_valid_scan_explanation_is_stripped() -> None:
    explanation = _explanation(
        summary="  One issue was blocked.  ",
        risk_explanation="  It may expose sensitive data.  ",
        safe_remediation="  Review the affected rule.  ",
        confidence="high",
    )

    assert explanation.summary == "One issue was blocked."
    assert explanation.risk_explanation == ("It may expose sensitive data.")
    assert explanation.safe_remediation == ("Review the affected rule.")
    assert explanation.confidence == "high"


@pytest.mark.parametrize(
    "field_name",
    (
        "summary",
        "risk_explanation",
        "safe_remediation",
    ),
)
@pytest.mark.parametrize(
    "unsafe_value",
    (
        "",
        " ",
        "line one\nline two",
        "x" * 301,
    ),
)
def test_invalid_scan_explanation_text_is_rejected(
    field_name: str,
    unsafe_value: str,
) -> None:
    with pytest.raises(ValidationError):
        _explanation(
            **{
                field_name: unsafe_value,
            }
        )


@pytest.mark.parametrize(
    "confidence",
    (
        "",
        "certain",
        "HIGH",
        "high ",
    ),
)
def test_invalid_scan_confidence_is_rejected(
    confidence: str,
) -> None:
    with pytest.raises(ValidationError):
        _explanation(
            confidence=confidence,
        )


def test_scan_explanation_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        _explanation(
            command="run deployment",
        )


def test_scan_explanation_is_frozen() -> None:
    explanation = _explanation()

    with pytest.raises(ValidationError):
        explanation.summary = "changed"  # type: ignore[misc]

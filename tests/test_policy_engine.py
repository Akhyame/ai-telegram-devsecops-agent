import pytest

import policy_engine
from policy_engine import (
    Finding,
    GateDecision,
    SecurityPolicy,
    Severity,
    evaluate_findings,
)


def _finding(
    severity: Severity,
    rule_id: str = "test-rule",
) -> Finding:
    return Finding(
        source="test-scanner",
        rule_id=rule_id,
        severity=severity,
        title="Redacted security finding",
        location="example.py:10",
    )


def test_empty_findings_are_allowed() -> None:
    result = evaluate_findings([])

    assert result.decision is GateDecision.ALLOW
    assert result.is_allowed is True
    assert result.total_findings == 0
    assert result.blocking_findings == ()
    assert result.reasons == ()


@pytest.mark.parametrize(
    "severity",
    [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
    ],
)
def test_non_blocking_severities_are_allowed(
    severity: Severity,
) -> None:
    result = evaluate_findings([_finding(severity)])

    assert result.decision is GateDecision.ALLOW
    assert result.is_allowed is True


@pytest.mark.parametrize(
    "severity",
    [
        Severity.HIGH,
        Severity.CRITICAL,
    ],
)
def test_high_and_critical_findings_are_blocked(
    severity: Severity,
) -> None:
    finding = _finding(severity)
    result = evaluate_findings([finding])

    assert result.decision is GateDecision.BLOCK
    assert result.is_allowed is False
    assert result.blocking_findings == (finding,)


def test_unknown_severity_is_blocked_by_default() -> None:
    finding = _finding(Severity.UNKNOWN)
    result = evaluate_findings([finding])

    assert result.decision is GateDecision.BLOCK
    assert result.blocking_findings == (finding,)
    assert result.reasons == ("test-scanner:test-rule has an unknown severity",)


def test_unknown_severity_can_be_allowed_by_policy() -> None:
    policy = SecurityPolicy(block_on_unknown=False)

    result = evaluate_findings(
        [_finding(Severity.UNKNOWN)],
        policy=policy,
    )

    assert result.decision is GateDecision.ALLOW
    assert result.blocking_findings == ()


def test_total_count_and_blocking_order_are_preserved() -> None:
    findings = (
        _finding(Severity.LOW, "low-rule"),
        _finding(Severity.CRITICAL, "critical-rule"),
        _finding(Severity.HIGH, "high-rule"),
        _finding(Severity.INFO, "info-rule"),
    )

    result = evaluate_findings(findings)

    assert result.total_findings == 4
    assert result.blocking_findings == (
        findings[1],
        findings[2],
    )
    assert result.reasons == (
        "test-scanner:critical-rule has blocked severity critical",
        "test-scanner:high-rule has blocked severity high",
    )


def test_public_api_exports_expected_members() -> None:
    expected_exports = {
        "Finding",
        "GateDecision",
        "GateResult",
        "PolicyConfigurationError",
        "ReportValidationError",
        "SecurityPolicy",
        "Severity",
        "evaluate_findings",
        "load_gitleaks_report",
        "load_pip_audit_report",
        "load_security_policy",
        "load_semgrep_report",
        "load_trivy_report",
    }

    assert set(policy_engine.__all__) == expected_exports

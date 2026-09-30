from collections.abc import Iterable

from policy_engine.models import (
    Finding,
    GateDecision,
    GateResult,
    SecurityPolicy,
    Severity,
)


def evaluate_findings(
    findings: Iterable[Finding],
    policy: SecurityPolicy | None = None,
) -> GateResult:
    active_policy = policy or SecurityPolicy()
    all_findings = tuple(findings)

    blocking_findings = tuple(
        finding
        for finding in all_findings
        if finding.severity in active_policy.blocked_severities
        or (active_policy.block_on_unknown and finding.severity is Severity.UNKNOWN)
    )

    decision = GateDecision.BLOCK if blocking_findings else GateDecision.ALLOW

    reasons = tuple(_blocking_reason(finding) for finding in blocking_findings)

    return GateResult(
        decision=decision,
        total_findings=len(all_findings),
        blocking_findings=blocking_findings,
        reasons=reasons,
    )


def _blocking_reason(finding: Finding) -> str:
    if finding.severity is Severity.UNKNOWN:
        return f"{finding.source}:{finding.rule_id} has an unknown severity"

    return f"{finding.source}:{finding.rule_id} has blocked severity {finding.severity.value}"

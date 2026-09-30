import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from policy_engine.config import load_security_policy
from policy_engine.errors import PolicyConfigurationError, ReportValidationError
from policy_engine.evaluator import evaluate_findings
from policy_engine.models import Finding, GateDecision, GateResult
from policy_engine.parsers import (
    load_gitleaks_report,
    load_pip_audit_report,
    load_semgrep_report,
    load_trivy_report,
)

_ALLOW_EXIT_CODE = 0
_BLOCK_EXIT_CODE = 1
_ERROR_EXIT_CODE = 2


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Evaluate security scanner reports against the project policy."
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("security-policy.toml"),
    )
    parser.add_argument(
        "--gitleaks-report",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--pip-audit-report",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--semgrep-report",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--trivy-report",
        type=Path,
        action="append",
        required=True,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("security-gate-result.json"),
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    options = parser.parse_args(arguments)

    try:
        policy = load_security_policy(options.policy)
        findings = _load_findings(
            gitleaks_report=options.gitleaks_report,
            pip_audit_report=options.pip_audit_report,
            semgrep_report=options.semgrep_report,
            trivy_reports=options.trivy_report,
        )
        result = evaluate_findings(findings, policy=policy)
    except (PolicyConfigurationError, ReportValidationError) as exc:
        summary = {
            "decision": "error",
            "error": str(exc),
        }

        if not _write_summary(options.output, summary):
            return _ERROR_EXIT_CODE

        print(f"Security gate error: {exc}", file=sys.stderr)
        return _ERROR_EXIT_CODE

    if not _write_summary(options.output, _result_summary(result)):
        return _ERROR_EXIT_CODE

    print(
        "Security gate decision: "
        f"{result.decision.value.upper()} "
        f"({len(result.blocking_findings)}/{result.total_findings} blocking findings)"
    )

    if result.decision is GateDecision.BLOCK:
        for reason in result.reasons:
            print(f"Security gate blocker: {reason}")
        return _BLOCK_EXIT_CODE

    return _ALLOW_EXIT_CODE


def _load_findings(
    *,
    gitleaks_report: Path,
    pip_audit_report: Path,
    semgrep_report: Path,
    trivy_reports: Sequence[Path],
) -> tuple[Finding, ...]:
    findings = [
        *load_gitleaks_report(gitleaks_report),
        *load_pip_audit_report(pip_audit_report),
        *load_semgrep_report(semgrep_report),
    ]

    for report_path in trivy_reports:
        findings.extend(load_trivy_report(report_path))

    return tuple(findings)


def _result_summary(result: GateResult) -> dict[str, object]:
    return {
        "decision": result.decision.value,
        "total_findings": result.total_findings,
        "blocking_findings": len(result.blocking_findings),
        "reasons": list(result.reasons),
    }


def _write_summary(
    output_path: Path,
    summary: dict[str, object],
) -> bool:
    try:
        output_path.write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        print(
            f"Security gate error: unable to write result file: {output_path.name}",
            file=sys.stderr,
        )
        return False

    return True


if __name__ == "__main__":
    raise SystemExit(main())

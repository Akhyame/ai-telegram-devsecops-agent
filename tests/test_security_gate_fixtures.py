import json
from pathlib import Path

import policy_engine.cli as cli

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "security_gate"


def _arguments(
    output_path: Path,
    *,
    gitleaks_report: Path | None = None,
    semgrep_report: Path | None = None,
) -> list[str]:
    allow_directory = _FIXTURE_ROOT / "allow"

    return [
        "--policy",
        str(_PROJECT_ROOT / "security-policy.toml"),
        "--gitleaks-report",
        str(gitleaks_report or allow_directory / "gitleaks-report.json"),
        "--pip-audit-report",
        str(allow_directory / "pip-audit-report.json"),
        "--semgrep-report",
        str(semgrep_report or allow_directory / "semgrep-report.json"),
        "--trivy-report",
        str(allow_directory / "trivy-filesystem-report.json"),
        "--trivy-report",
        str(allow_directory / "trivy-image-report.json"),
        "--output",
        str(output_path),
    ]


def test_representative_reports_are_allowed(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "allow-result.json"

    exit_code = cli.main(_arguments(output_path))

    assert exit_code == 0
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "blocking_findings": 0,
        "decision": "allow",
        "reasons": [],
        "total_findings": 1,
    }


def test_representative_high_finding_is_blocked_without_secret_exposure(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "block-result.json"
    gitleaks_report = _FIXTURE_ROOT / "block" / "gitleaks-report.json"

    exit_code = cli.main(
        _arguments(
            output_path,
            gitleaks_report=gitleaks_report,
        )
    )

    output_text = output_path.read_text(encoding="utf-8")

    assert exit_code == 1
    assert json.loads(output_text) == {
        "blocking_findings": 1,
        "decision": "block",
        "reasons": [
            "gitleaks:fixture-secret-rule has blocked severity high",
        ],
        "total_findings": 2,
    }
    assert "fixture-secret-value" not in output_text
    assert "fixture-match-value" not in output_text


def test_representative_scan_error_fails_closed_without_detail_exposure(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "error-result.json"
    semgrep_report = _FIXTURE_ROOT / "invalid" / "semgrep-report.json"

    exit_code = cli.main(
        _arguments(
            output_path,
            semgrep_report=semgrep_report,
        )
    )

    output_text = output_path.read_text(encoding="utf-8")

    assert exit_code == 2
    assert json.loads(output_text) == {
        "decision": "error",
        "error": "Semgrep report contains scan errors",
    }
    assert "untrusted-fixture-error-detail" not in output_text

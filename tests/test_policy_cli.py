import json
from pathlib import Path

import pytest

import policy_engine.cli as cli
from policy_engine import (
    Finding,
    PolicyConfigurationError,
    ReportValidationError,
    SecurityPolicy,
    Severity,
)


def _arguments(
    temporary_path: Path,
    *,
    trivy_reports: tuple[str, ...] = ("trivy-filesystem.json",),
) -> tuple[list[str], Path]:
    output_path = temporary_path / "security-gate-result.json"

    arguments = [
        "--policy",
        str(temporary_path / "security-policy.toml"),
        "--gitleaks-report",
        str(temporary_path / "gitleaks.json"),
        "--pip-audit-report",
        str(temporary_path / "pip-audit.json"),
        "--semgrep-report",
        str(temporary_path / "semgrep.json"),
    ]

    for report_name in trivy_reports:
        arguments.extend(
            [
                "--trivy-report",
                str(temporary_path / report_name),
            ]
        )

    arguments.extend(
        [
            "--output",
            str(output_path),
        ]
    )

    return arguments, output_path


def _patch_successful_loaders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "load_security_policy",
        lambda _: SecurityPolicy(),
    )
    monkeypatch.setattr(
        cli,
        "load_gitleaks_report",
        lambda _: (),
    )
    monkeypatch.setattr(
        cli,
        "load_pip_audit_report",
        lambda _: (),
    )
    monkeypatch.setattr(
        cli,
        "load_semgrep_report",
        lambda _: (),
    )
    monkeypatch.setattr(
        cli,
        "load_trivy_report",
        lambda _: (),
    )


def _finding(
    severity: Severity,
    *,
    source: str = "test-scanner",
    rule_id: str = "test-rule",
) -> Finding:
    return Finding(
        source=source,
        rule_id=rule_id,
        severity=severity,
        title="Controlled security finding",
        location="example.py:10",
    )


def test_allowed_reports_return_zero_and_write_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_successful_loaders(monkeypatch)
    arguments, output_path = _arguments(tmp_path)

    exit_code = cli.main(arguments)

    assert exit_code == 0
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "blocking_findings": 0,
        "decision": "allow",
        "reasons": [],
        "total_findings": 0,
    }
    assert "Security gate decision: ALLOW" in capsys.readouterr().out


def test_blocking_finding_returns_one_and_writes_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_successful_loaders(monkeypatch)
    monkeypatch.setattr(
        cli,
        "load_gitleaks_report",
        lambda _: (_finding(Severity.HIGH, source="gitleaks"),),
    )
    arguments, output_path = _arguments(tmp_path)

    exit_code = cli.main(arguments)

    assert exit_code == 1
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "blocking_findings": 1,
        "decision": "block",
        "reasons": [
            "gitleaks:test-rule has blocked severity high",
        ],
        "total_findings": 1,
    }
    assert "Security gate decision: BLOCK" in capsys.readouterr().out


def test_multiple_trivy_reports_are_combined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_successful_loaders(monkeypatch)

    loaded_reports: list[str] = []

    def load_trivy(report_path: Path) -> tuple[Finding, ...]:
        loaded_reports.append(report_path.name)

        return (
            _finding(
                Severity.LOW,
                source="trivy",
                rule_id=report_path.stem,
            ),
        )

    monkeypatch.setattr(
        cli,
        "load_trivy_report",
        load_trivy,
    )
    arguments, output_path = _arguments(
        tmp_path,
        trivy_reports=(
            "trivy-filesystem.json",
            "trivy-image.json",
        ),
    )

    exit_code = cli.main(arguments)

    assert exit_code == 0
    assert loaded_reports == [
        "trivy-filesystem.json",
        "trivy-image.json",
    ]
    assert json.loads(output_path.read_text(encoding="utf-8"))["total_findings"] == 2


def test_policy_configuration_error_returns_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_successful_loaders(monkeypatch)

    def reject_policy(_: Path) -> SecurityPolicy:
        raise PolicyConfigurationError("Security policy is invalid")

    monkeypatch.setattr(
        cli,
        "load_security_policy",
        reject_policy,
    )
    arguments, output_path = _arguments(tmp_path)

    exit_code = cli.main(arguments)

    assert exit_code == 2
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "decision": "error",
        "error": "Security policy is invalid",
    }
    assert "Security gate error" in capsys.readouterr().err


def test_report_validation_error_returns_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_successful_loaders(monkeypatch)

    def reject_report(_: Path) -> tuple[Finding, ...]:
        raise ReportValidationError("Scanner report is invalid")

    monkeypatch.setattr(
        cli,
        "load_semgrep_report",
        reject_report,
    )
    arguments, output_path = _arguments(tmp_path)

    exit_code = cli.main(arguments)

    assert exit_code == 2
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "decision": "error",
        "error": "Scanner report is invalid",
    }
    assert "Security gate error" in capsys.readouterr().err


def test_unwritable_output_returns_two(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _patch_successful_loaders(monkeypatch)
    arguments, _ = _arguments(tmp_path)

    arguments[-1] = str(tmp_path)

    exit_code = cli.main(arguments)

    assert exit_code == 2
    assert "unable to write result file" in capsys.readouterr().err


def test_missing_required_arguments_return_two() -> None:
    with pytest.raises(SystemExit) as raised_exit:
        cli.main([])

    assert raised_exit.value.code == 2

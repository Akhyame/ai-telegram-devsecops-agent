"""Offline tests for fail-closed CI deployment validation."""

import json
from pathlib import Path

import pytest

from deployment.ci_gate import (
    MAX_GATE_REPORT_BYTES,
    main,
    validate_deployment_request,
)
from deployment.models import DeploymentEnvironment
from policy_engine.models import GateDecision

_PROJECT_ID = 123456
_PIPELINE_ID = 654321
_REF = "main"
_SHA = "a" * 40
_REPOSITORY = "registry.gitlab.com/example/project"


def _gate_report(
    tmp_path: Path,
    **overrides: object,
) -> Path:
    report: dict[str, object] = {
        "decision": "allow",
        "total_findings": 5,
        "blocking_findings": 0,
        "reasons": [],
    }
    report.update(overrides)

    path = tmp_path / "security-gate-result.json"
    path.write_text(
        json.dumps(report),
        encoding="utf-8",
    )

    return path


def _arguments(
    tmp_path: Path,
    **overrides: str,
) -> tuple[list[str], Path]:
    output = tmp_path / "deployment.env"

    if "gate_report" in overrides:
        gate_report = overrides.pop("gate_report")
    else:
        gate_report = str(_gate_report(tmp_path))

    values = {
        "environment": "staging",
        "project_id": str(_PROJECT_ID),
        "pipeline_id": str(_PIPELINE_ID),
        "ref": _REF,
        "commit_sha": _SHA,
        "image_repository": _REPOSITORY,
        "gate_report": gate_report,
        "dotenv_output": str(output),
    }
    values.update(overrides)

    arguments = [
        "--environment",
        values["environment"],
        "--project-id",
        values["project_id"],
        "--pipeline-id",
        values["pipeline_id"],
        "--ref",
        values["ref"],
        "--commit-sha",
        values["commit_sha"],
        "--image-repository",
        values["image_repository"],
        "--gate-report",
        values["gate_report"],
        "--dotenv-output",
        values["dotenv_output"],
    ]

    return arguments, output


def test_valid_gate_emits_only_non_secret_bound_values(
    tmp_path: Path,
) -> None:
    arguments, output = _arguments(tmp_path)

    assert main(arguments) == 0

    assert output.read_text(encoding="utf-8") == (
        "DEPLOYMENT_ENVIRONMENT=staging\n"
        f"DEPLOYMENT_IMAGE_REPOSITORY={_REPOSITORY}\n"
        f"DEPLOYMENT_COMMIT_SHA={_SHA}\n"
    )


def test_valid_contract_uses_existing_strict_models(
    tmp_path: Path,
) -> None:
    request = validate_deployment_request(
        environment="production",
        project_id=_PROJECT_ID,
        pipeline_id=_PIPELINE_ID,
        ref=_REF,
        commit_sha=_SHA,
        image_repository=_REPOSITORY,
        gate_report=_gate_report(tmp_path),
    )

    assert request.target.environment is DeploymentEnvironment.PRODUCTION
    assert request.gate.decision is GateDecision.ALLOW
    assert request.image.reference == f"{_REPOSITORY}:{_SHA}"


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("decision", "block"),
        ("blocking_findings", 1),
        ("total_findings", True),
        ("blocking_findings", False),
        ("reasons", [123]),
    ),
)
def test_invalid_gate_evidence_fails_closed(
    tmp_path: Path,
    field: str,
    invalid_value: object,
) -> None:
    report = _gate_report(
        tmp_path,
        **{field: invalid_value},
    )
    arguments, output = _arguments(
        tmp_path,
        gate_report=str(report),
    )

    assert main(arguments) == 2
    assert not output.exists()


def test_unknown_gate_key_is_rejected(
    tmp_path: Path,
) -> None:
    report = _gate_report(
        tmp_path,
        unexpected="value",
    )
    arguments, output = _arguments(
        tmp_path,
        gate_report=str(report),
    )

    assert main(arguments) == 2
    assert not output.exists()


def test_duplicate_gate_key_is_rejected(
    tmp_path: Path,
) -> None:
    report = tmp_path / "duplicate.json"
    report.write_text(
        (
            '{"decision":"allow","decision":"allow",'
            '"total_findings":0,"blocking_findings":0,"reasons":[]}'
        ),
        encoding="utf-8",
    )
    arguments, output = _arguments(
        tmp_path,
        gate_report=str(report),
    )

    assert main(arguments) == 2
    assert not output.exists()


def test_oversized_gate_report_is_rejected(
    tmp_path: Path,
) -> None:
    report = tmp_path / "oversized.json"
    report.write_bytes(b"x" * (MAX_GATE_REPORT_BYTES + 1))
    arguments, output = _arguments(
        tmp_path,
        gate_report=str(report),
    )

    assert main(arguments) == 2
    assert not output.exists()


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("environment", "development"),
        ("project_id", "0"),
        ("pipeline_id", "-1"),
        ("ref", "../main"),
        ("commit_sha", "abc123"),
        ("image_repository", "docker.io/example/project"),
    ),
)
def test_untrusted_ci_binding_is_rejected(
    tmp_path: Path,
    name: str,
    value: str,
) -> None:
    arguments, output = _arguments(
        tmp_path,
        **{name: value},
    )

    assert main(arguments) == 2
    assert not output.exists()


def test_failure_message_does_not_echo_untrusted_value(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = "DO_NOT_ECHO_THIS_VALUE"
    arguments, output = _arguments(
        tmp_path,
        image_repository=marker,
    )

    assert main(arguments) == 2
    assert not output.exists()

    captured = capsys.readouterr()

    assert captured.out == ""
    assert captured.err == "Deployment validation failed.\n"
    assert marker not in captured.err

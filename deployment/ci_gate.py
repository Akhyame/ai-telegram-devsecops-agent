"""Fail-closed validation of trusted CI evidence before deployment."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from deployment.models import (
    DeploymentEnvironment,
    DeploymentRequest,
    DeploymentTarget,
    ImmutableImageReference,
    PassedSecurityGateEvidence,
)
from policy_engine.models import GateDecision

MAX_GATE_REPORT_BYTES = 65_536
MAX_GATE_REASONS = 100
MAX_GATE_REASON_LENGTH = 500

_ALLOWED_GATE_KEYS = frozenset(
    {
        "decision",
        "total_findings",
        "blocking_findings",
        "reasons",
    }
)

_FAILURE_MESSAGE = "Deployment validation failed."


class DeploymentGateValidationError(ValueError):
    """Raised when CI deployment evidence is invalid."""


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise DeploymentGateValidationError("Security Gate report contains duplicate keys.")

        result[key] = value

    return result


def _load_gate_report(path: Path) -> dict[str, object]:
    try:
        report_bytes = path.read_bytes()
    except OSError as exc:
        raise DeploymentGateValidationError("Security Gate report could not be read.") from exc

    if not report_bytes or len(report_bytes) > MAX_GATE_REPORT_BYTES:
        raise DeploymentGateValidationError("Security Gate report size is invalid.")

    try:
        report = json.loads(
            report_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except DeploymentGateValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentGateValidationError("Security Gate report is invalid.") from exc

    if not isinstance(report, dict):
        raise DeploymentGateValidationError("Security Gate report must be an object.")

    if set(report) != _ALLOWED_GATE_KEYS:
        raise DeploymentGateValidationError("Security Gate report keys are invalid.")

    decision = report["decision"]
    total_findings = report["total_findings"]
    blocking_findings = report["blocking_findings"]
    reasons = report["reasons"]

    if not isinstance(decision, str):
        raise DeploymentGateValidationError("Security Gate decision is invalid.")

    if type(total_findings) is not int:
        raise DeploymentGateValidationError("Security Gate finding count is invalid.")

    if type(blocking_findings) is not int:
        raise DeploymentGateValidationError("Security Gate blocking count is invalid.")

    if (
        not isinstance(reasons, list)
        or len(reasons) > MAX_GATE_REASONS
        or any(
            not isinstance(reason, str) or not 1 <= len(reason) <= MAX_GATE_REASON_LENGTH
            for reason in reasons
        )
    ):
        raise DeploymentGateValidationError("Security Gate reasons are invalid.")

    return report


def validate_deployment_request(
    *,
    environment: str,
    project_id: int,
    pipeline_id: int,
    ref: str,
    commit_sha: str,
    image_repository: str,
    gate_report: Path,
) -> DeploymentRequest:
    """Build a strictly bound request from trusted CI variables and gate evidence."""

    report = _load_gate_report(gate_report)

    try:
        decision = GateDecision(report["decision"])
        deployment_environment = DeploymentEnvironment(environment)

        gate = PassedSecurityGateEvidence(
            project_id=project_id,
            pipeline_id=pipeline_id,
            ref=ref,
            commit_sha=commit_sha,
            decision=decision,
            total_findings=report["total_findings"],
            blocking_findings=report["blocking_findings"],
        )

        return DeploymentRequest(
            target=DeploymentTarget(
                environment=deployment_environment,
                project_id=project_id,
                ref=ref,
            ),
            image=ImmutableImageReference(
                repository=image_repository,
                commit_sha=commit_sha,
            ),
            gate=gate,
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise DeploymentGateValidationError("Deployment request is invalid.") from exc


def render_deployment_dotenv(
    request: DeploymentRequest,
) -> str:
    """Render the minimal non-secret deployment contract."""

    return "\n".join(
        (
            f"DEPLOYMENT_ENVIRONMENT={request.target.environment.value}",
            f"DEPLOYMENT_IMAGE_REPOSITORY={request.image.repository}",
            f"DEPLOYMENT_COMMIT_SHA={request.image.commit_sha}",
            "",
        )
    )


def build_argument_parser() -> argparse.ArgumentParser:
    """Build the bounded command-line interface."""

    parser = argparse.ArgumentParser()

    parser.add_argument("--environment", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--pipeline-id", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--image-repository", required=True)
    parser.add_argument(
        "--gate-report",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--dotenv-output",
        required=True,
        type=Path,
    )

    return parser


def main(
    arguments: Sequence[str] | None = None,
) -> int:
    """Validate deployment evidence and emit a safe dotenv artifact."""

    parser = build_argument_parser()
    args = parser.parse_args(arguments)

    try:
        request = validate_deployment_request(
            environment=args.environment,
            project_id=int(args.project_id),
            pipeline_id=int(args.pipeline_id),
            ref=args.ref,
            commit_sha=args.commit_sha,
            image_repository=args.image_repository,
            gate_report=args.gate_report,
        )

        dotenv_text = render_deployment_dotenv(request)

        args.dotenv_output.write_text(
            dotenv_text,
            encoding="utf-8",
            newline="\n",
        )
    except (
        DeploymentGateValidationError,
        OSError,
        TypeError,
        ValueError,
    ):
        print(
            _FAILURE_MESSAGE,
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

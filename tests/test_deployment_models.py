"""Offline tests for strict deployment contracts."""

from typing import Any

import pytest
from pydantic import ValidationError

from deployment.models import (
    DeploymentEnvironment,
    DeploymentRequest,
    DeploymentTarget,
    ImmutableImageReference,
    PassedSecurityGateEvidence,
)
from policy_engine.models import GateDecision

_PROJECT_ID = 85705009
_PIPELINE_ID = 123456
_REF = "main"
_SHA = "a" * 40
_REPOSITORY = "registry.gitlab.com/akhyames/ai-telegram-devsecops-agent"


def _image(
    **overrides: Any,
) -> ImmutableImageReference:
    values: dict[str, Any] = {
        "repository": _REPOSITORY,
        "commit_sha": _SHA,
    }
    values.update(overrides)
    return ImmutableImageReference(**values)


def _gate(
    **overrides: Any,
) -> PassedSecurityGateEvidence:
    values: dict[str, Any] = {
        "project_id": _PROJECT_ID,
        "pipeline_id": _PIPELINE_ID,
        "ref": _REF,
        "commit_sha": _SHA,
        "decision": GateDecision.ALLOW,
        "total_findings": 5,
        "blocking_findings": 0,
    }
    values.update(overrides)
    return PassedSecurityGateEvidence(**values)


def _target(
    **overrides: Any,
) -> DeploymentTarget:
    values: dict[str, Any] = {
        "environment": DeploymentEnvironment.STAGING,
        "project_id": _PROJECT_ID,
        "ref": _REF,
    }
    values.update(overrides)
    return DeploymentTarget(**values)


def _request(
    **overrides: Any,
) -> DeploymentRequest:
    values: dict[str, Any] = {
        "target": _target(),
        "image": _image(),
        "gate": _gate(),
    }
    values.update(overrides)
    return DeploymentRequest(**values)


def test_deployment_environments_are_exact() -> None:
    assert list(DeploymentEnvironment) == [
        DeploymentEnvironment.STAGING,
        DeploymentEnvironment.PRODUCTION,
    ]


def test_image_reference_is_derived_from_repository_and_sha() -> None:
    image = _image()

    assert image.reference == f"{_REPOSITORY}:{_SHA}"


@pytest.mark.parametrize(
    "repository",
    (
        "https://registry.gitlab.com/akhyames/project",
        "docker.io/akhyames/project",
        "registry.gitlab.com/Akhyames/project",
        "registry.gitlab.com/akhyames//project",
        "registry.gitlab.com/akhyames/../project",
        "registry.gitlab.com/akhyames/project/",
        "registry.gitlab.com/akhyames/project:latest",
        " registry.gitlab.com/akhyames/project",
    ),
)
def test_invalid_image_repositories_are_rejected(
    repository: str,
) -> None:
    with pytest.raises(ValidationError):
        _image(repository=repository)


@pytest.mark.parametrize(
    "commit_sha",
    (
        "a" * 39,
        "a" * 41,
        "A" * 40,
        "g" * 40,
        f"{'a' * 40} ",
        "main",
    ),
)
def test_invalid_commit_shas_are_rejected(
    commit_sha: str,
) -> None:
    with pytest.raises(ValidationError):
        _image(commit_sha=commit_sha)


def test_allowed_gate_evidence_is_accepted() -> None:
    gate = _gate()

    assert gate.decision is GateDecision.ALLOW
    assert gate.blocking_findings == 0


@pytest.mark.parametrize(
    "overrides",
    (
        {"decision": GateDecision.BLOCK},
        {"blocking_findings": 1},
        {"project_id": True},
        {"pipeline_id": 0},
        {"ref": "../main"},
        {"ref": "main.lock"},
        {"commit_sha": "A" * 40},
        {"total_findings": 1001},
    ),
)
def test_unsafe_gate_evidence_is_rejected(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        _gate(**overrides)


@pytest.mark.parametrize(
    "overrides",
    (
        {"environment": "staging"},
        {"project_id": True},
        {"ref": "feature//unsafe"},
        {"ref": "main."},
    ),
)
def test_unsafe_deployment_targets_are_rejected(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        _target(**overrides)


def test_matching_deployment_request_is_accepted() -> None:
    request = _request()

    assert request.target.environment is DeploymentEnvironment.STAGING
    assert request.image.commit_sha == request.gate.commit_sha


@pytest.mark.parametrize(
    "overrides",
    (
        {
            "target": _target(
                project_id=_PROJECT_ID + 1,
            )
        },
        {
            "target": _target(
                ref="release",
            )
        },
        {
            "image": _image(
                commit_sha="b" * 40,
            )
        },
    ),
)
def test_mismatched_deployment_evidence_is_rejected(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        _request(**overrides)


def test_extra_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        DeploymentTarget(
            environment=DeploymentEnvironment.STAGING,
            project_id=_PROJECT_ID,
            ref=_REF,
            host="untrusted.example",
        )


def test_contracts_are_frozen() -> None:
    request = _request()

    with pytest.raises(ValidationError):
        request.target = _target(
            environment=DeploymentEnvironment.PRODUCTION,
        )

"""Strict contracts for controlled immutable deployments."""

import re
from enum import StrEnum
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from policy_engine.models import GateDecision

MAX_GITLAB_IDENTIFIER = (2**63) - 1
MAX_SECURITY_FINDINGS = 1000

_IMAGE_REGISTRY_PREFIX = "registry.gitlab.com/"
_IMAGE_SEGMENT_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?")
_REF_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
_COMMIT_SHA_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class DeploymentEnvironment(StrEnum):
    """Allowlisted deployment environments."""

    STAGING = "staging"
    PRODUCTION = "production"


class ImmutableImageReference(BaseModel):
    """Commit-SHA-addressed image in the project GitLab registry."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    repository: str = Field(
        min_length=1,
        max_length=255,
    )
    commit_sha: str = Field(
        min_length=40,
        max_length=64,
    )

    @field_validator(
        "repository",
        mode="before",
    )
    @classmethod
    def _validate_repository(
        cls,
        value: object,
    ) -> object:
        if not isinstance(value, str):
            return value

        if not value.startswith(_IMAGE_REGISTRY_PREFIX):
            raise ValueError("Image repository is not allowlisted.")

        path = value.removeprefix(_IMAGE_REGISTRY_PREFIX)
        segments = path.split("/")

        if len(segments) < 2 or any(
            _IMAGE_SEGMENT_PATTERN.fullmatch(segment) is None for segment in segments
        ):
            raise ValueError("Image repository is invalid.")

        return value

    @field_validator(
        "commit_sha",
        mode="before",
    )
    @classmethod
    def _validate_commit_sha(
        cls,
        value: object,
    ) -> object:
        return _validated_commit_sha(value)

    @property
    def reference(self) -> str:
        """Return the immutable commit-SHA image reference."""

        return f"{self.repository}:{self.commit_sha}"


class PassedSecurityGateEvidence(BaseModel):
    """Minimal trusted evidence proving that the Security Gate allowed release."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    project_id: int = Field(
        gt=0,
        le=MAX_GITLAB_IDENTIFIER,
    )
    pipeline_id: int = Field(
        gt=0,
        le=MAX_GITLAB_IDENTIFIER,
    )
    ref: str = Field(
        min_length=1,
        max_length=128,
    )
    commit_sha: str = Field(
        min_length=40,
        max_length=64,
    )
    decision: GateDecision
    total_findings: int = Field(
        ge=0,
        le=MAX_SECURITY_FINDINGS,
    )
    blocking_findings: int = Field(
        ge=0,
        le=MAX_SECURITY_FINDINGS,
    )

    @field_validator(
        "ref",
        mode="before",
    )
    @classmethod
    def _validate_ref(
        cls,
        value: object,
    ) -> object:
        return _validated_ref(value)

    @field_validator(
        "commit_sha",
        mode="before",
    )
    @classmethod
    def _validate_commit_sha(
        cls,
        value: object,
    ) -> object:
        return _validated_commit_sha(value)

    @model_validator(mode="after")
    def _validate_passed_gate(self) -> Self:
        if self.decision is not GateDecision.ALLOW:
            raise ValueError("Deployment requires an allowed Security Gate.")

        if self.blocking_findings != 0:
            raise ValueError("Passed Security Gate evidence cannot be blocking.")

        return self


class DeploymentTarget(BaseModel):
    """Allowlisted environment and fixed GitLab project/ref target."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    environment: DeploymentEnvironment
    project_id: int = Field(
        gt=0,
        le=MAX_GITLAB_IDENTIFIER,
    )
    ref: str = Field(
        min_length=1,
        max_length=128,
    )

    @field_validator(
        "ref",
        mode="before",
    )
    @classmethod
    def _validate_ref(
        cls,
        value: object,
    ) -> object:
        return _validated_ref(value)


class DeploymentRequest(BaseModel):
    """Matched deployment target, immutable image, and passed gate evidence."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
    )

    target: DeploymentTarget
    image: ImmutableImageReference
    gate: PassedSecurityGateEvidence

    @model_validator(mode="after")
    def _validate_evidence_binding(self) -> Self:
        if self.target.project_id != self.gate.project_id:
            raise ValueError("Deployment project does not match gate evidence.")

        if self.target.ref != self.gate.ref:
            raise ValueError("Deployment ref does not match gate evidence.")

        if self.image.commit_sha != self.gate.commit_sha:
            raise ValueError("Deployment image does not match gate evidence.")

        return self


def _validated_ref(
    value: object,
) -> object:
    if not isinstance(value, str):
        return value

    unsafe_sequences = (
        "..",
        "//",
        "@{",
    )

    if (
        _REF_PATTERN.fullmatch(value) is None
        or any(sequence in value for sequence in unsafe_sequences)
        or value.endswith(("/", ".", ".lock"))
    ):
        raise ValueError("Deployment ref is invalid.")

    return value


def _validated_commit_sha(
    value: object,
) -> object:
    if not isinstance(value, str):
        return value

    if _COMMIT_SHA_PATTERN.fullmatch(value) is None:
        raise ValueError("Deployment commit SHA is invalid.")

    return value

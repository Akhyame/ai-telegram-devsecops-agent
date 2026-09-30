"""Strict normalized input and structured output contracts for local AI."""

import unicodedata
from enum import StrEnum
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class PipelineJob(StrEnum):
    """Allowlisted CI jobs that can be explained."""

    RUNNER_CONNECTIVITY = "runner_connectivity"
    RUFF_QUALITY = "ruff_quality"
    UNIT_TESTS = "unit_tests"
    SECRET_SCAN = "secret_scan"  # noqa: S105
    DEPENDENCY_SCAN = "dependency_scan"
    SAST_SCAN = "sast_scan"
    TRIVY_FILESYSTEM_SCAN = "trivy_filesystem_scan"
    CONTAINER_IMAGE = "container_image"
    TRIVY_IMAGE_SCAN = "trivy_image_scan"
    SECURITY_GATE = "security_gate"


class FailureCode(StrEnum):
    """Deterministic failure categories produced before AI inference."""

    RUNNER_UNAVAILABLE = "runner_unavailable"
    QUALITY_CHECK_FAILED = "quality_check_failed"
    UNIT_TESTS_FAILED = "unit_tests_failed"
    SECRET_SCAN_FAILED = "secret_scan_failed"  # noqa: S105
    DEPENDENCY_SCAN_FAILED = "dependency_scan_failed"
    SAST_SCAN_FAILED = "sast_scan_failed"
    FILESYSTEM_SCAN_FAILED = "filesystem_scan_failed"
    CONTAINER_BUILD_FAILED = "container_build_failed"
    IMAGE_SCAN_FAILED = "image_scan_failed"
    SECURITY_GATE_FAILED = "security_gate_failed"
    SECURITY_GATE_BLOCKED = "security_gate_blocked"
    DEPENDENCY_DOWNLOAD_TIMEOUT = "dependency_download_timeout"
    UNKNOWN_FAILURE = "unknown_failure"


class Confidence(StrEnum):
    """Bounded confidence labels accepted from the model."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class NormalizedFailure(BaseModel):
    """Allowlisted metadata passed to AI instead of raw scanner or job text."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    job: PipelineJob
    failure_code: FailureCode
    blocking_findings: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )
    total_findings: int | None = Field(
        default=None,
        ge=0,
        le=1000,
    )

    @model_validator(mode="after")
    def _validate_finding_counts(self) -> Self:
        blocking = self.blocking_findings
        total = self.total_findings

        if (blocking is None) is not (total is None):
            raise ValueError("Finding counts must be provided together.")

        if self.failure_code is FailureCode.SECURITY_GATE_BLOCKED:
            if blocking is None or total is None:
                raise ValueError("A blocked security gate requires finding evidence.")

            if blocking > total:
                raise ValueError("Blocking findings cannot exceed total findings.")

            if blocking < 1:
                raise ValueError("A blocked security gate requires a blocking finding.")

            return self

        if blocking is not None or total is not None:
            raise ValueError("Finding counts are allowed only for a blocked security gate.")

        return self


class FailureExplanation(BaseModel):
    """Validated structured explanation returned by local AI."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    summary: str = Field(
        min_length=1,
        max_length=300,
    )
    likely_cause: str = Field(
        min_length=1,
        max_length=300,
    )
    safe_next_step: str = Field(
        min_length=1,
        max_length=300,
    )
    confidence: Confidence

    @field_validator(
        "summary",
        "likely_cause",
        "safe_next_step",
        mode="before",
    )
    @classmethod
    def _validate_plain_single_line_text(
        cls,
        value: object,
    ) -> object:
        if not isinstance(value, str):
            return value

        normalized = value.strip()

        if any(unicodedata.category(character).startswith("C") for character in normalized):
            raise ValueError("AI explanation text contains unsafe control characters.")

        return normalized

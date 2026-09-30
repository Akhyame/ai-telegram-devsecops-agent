"""Deterministic normalization of sanitized GitLab job failures."""

import re

from agent.models import (
    FailureCode,
    NormalizedFailure,
    PipelineJob,
)
from bot.gitlab_client import PipelineStatus
from bot.gitlab_logs import (
    MAX_LOG_OUTPUT_CHARACTERS,
    JobLogSummary,
    JobSummary,
)

_TIMEOUT_PATTERN = re.compile(
    r"""(?ix)
    \b(?:
        read \s+ timed \s+ out
        | readtimeout(?:error)?
        | dependency \s+ download .{0,80} timeout
    )\b
    """
)

_DEFAULT_FAILURE_CODES = {
    PipelineJob.RUNNER_CONNECTIVITY: FailureCode.RUNNER_UNAVAILABLE,
    PipelineJob.RUFF_QUALITY: FailureCode.QUALITY_CHECK_FAILED,
    PipelineJob.UNIT_TESTS: FailureCode.UNIT_TESTS_FAILED,
    PipelineJob.SECRET_SCAN: FailureCode.SECRET_SCAN_FAILED,
    PipelineJob.DEPENDENCY_SCAN: FailureCode.DEPENDENCY_SCAN_FAILED,
    PipelineJob.SAST_SCAN: FailureCode.SAST_SCAN_FAILED,
    PipelineJob.TRIVY_FILESYSTEM_SCAN: FailureCode.FILESYSTEM_SCAN_FAILED,
    PipelineJob.CONTAINER_IMAGE: FailureCode.CONTAINER_BUILD_FAILED,
    PipelineJob.TRIVY_IMAGE_SCAN: FailureCode.IMAGE_SCAN_FAILED,
    PipelineJob.SECURITY_GATE: FailureCode.SECURITY_GATE_FAILED,
}


class FailureNormalizationError(RuntimeError):
    """Raised when sanitized job metadata cannot be safely normalized."""


def normalize_job_failure(
    summary: JobLogSummary,
) -> NormalizedFailure:
    """Convert one sanitized failed job into allowlisted metadata only."""

    if not isinstance(summary, JobLogSummary):
        raise TypeError("A sanitized job log summary is required.")

    if (
        not isinstance(summary.job, JobSummary)
        or summary.job.status is not PipelineStatus.FAILED
        or not isinstance(summary.text, str)
        or not summary.text
        or len(summary.text) > MAX_LOG_OUTPUT_CHARACTERS
        or not isinstance(summary.truncated, bool)
    ):
        raise FailureNormalizationError("GitLab job failure cannot be normalized.")

    try:
        job = PipelineJob(summary.job.name)
    except ValueError:
        raise FailureNormalizationError("GitLab job failure cannot be normalized.") from None

    if _TIMEOUT_PATTERN.search(summary.text) is not None:
        failure_code = FailureCode.DEPENDENCY_DOWNLOAD_TIMEOUT
    else:
        failure_code = _DEFAULT_FAILURE_CODES[job]

    return NormalizedFailure(
        job=job,
        failure_code=failure_code,
    )

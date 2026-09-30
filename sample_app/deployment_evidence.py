"""Strict deployment evidence derived from bounded GitLab job traces."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx

from bot.gitlab_config import GitLabSettings
from sample_app.webhook_events import PipelineWebhookEvent

MAX_DEPLOYMENT_TRACE_BYTES = 32_768
MAX_DEPLOYMENT_JOBS_BYTES = 65_536

_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_GITLAB_TRACE_PREFIX_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?Z "
    r"\d{2}[A-Z] "
)

_DEPLOYMENT_JOB_ENVIRONMENTS = {
    "deploy_staging": "staging",
    "deploy_production": "production",
}

_TERMINAL_JOB_STATUSES = frozenset(
    {
        "success",
        "failed",
    }
)

_DEPLOYED_MARKER = "DEPLOYMENT_RESULT=deployed ROLLBACK=not_required"
_CONFIGURATION_FAILED_MARKER = "DEPLOYMENT_RESULT=configuration_failed"
_PREVIOUS_RELEASE_INVALID_MARKER = "DEPLOYMENT_RESULT=previous_release_invalid"
_DEPLOYMENT_FAILED_MARKER = "DEPLOYMENT_RESULT=failed ROLLBACK=required"

_ROLLBACK_MARKERS = {
    "ROLLBACK_RESULT=unavailable": "unavailable",
    "ROLLBACK_RESULT=succeeded": "succeeded",
    "ROLLBACK_RESULT=failed": "failed",
}


class DeploymentEvidenceError(RuntimeError):
    """Raised when trusted deployment evidence cannot be established."""


class DeploymentResultStatus(StrEnum):
    """Controlled deployment outcomes emitted by release.sh."""

    DEPLOYED = "deployed"
    CONFIGURATION_FAILED = "configuration_failed"
    PREVIOUS_RELEASE_INVALID = "previous_release_invalid"
    DEPLOYMENT_FAILED = "deployment_failed"
    DEPLOYMENT_FAILED_ROLLED_BACK = "deployment_failed_rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class DeploymentEnvironment(StrEnum):
    """Deployment environments fixed by server-side policy."""

    STAGING = "staging"
    PRODUCTION = "production"


class RollbackStatus(StrEnum):
    """Normalized rollback state."""

    NOT_REQUIRED = "not_required"
    NOT_ATTEMPTED = "not_attempted"
    UNAVAILABLE = "unavailable"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class DeploymentEvidence:
    """Minimal deployment facts safe for notification formatting."""

    status: DeploymentResultStatus
    environment: DeploymentEnvironment
    target_commit_sha: str
    rollback: RollbackStatus


def _evidence_error() -> DeploymentEvidenceError:
    return DeploymentEvidenceError("Deployment evidence is unavailable.")


def _is_positive_identifier(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _normalized_trace_lines(body: bytes) -> tuple[str, ...]:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _evidence_error() from exc

    text = _ANSI_ESCAPE_PATTERN.sub("", text)
    normalized_lines: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        line = _GITLAB_TRACE_PREFIX_PATTERN.sub(
            "",
            line,
            count=1,
        )

        normalized_lines.append(line)

    return tuple(normalized_lines)


def _count_marker(
    lines: tuple[str, ...],
    marker: str,
) -> int:
    return sum(line == marker for line in lines)


def _parse_trace(
    body: bytes,
    *,
    event: PipelineWebhookEvent,
    job_name: str,
) -> DeploymentEvidence:
    environment_value = _DEPLOYMENT_JOB_ENVIRONMENTS.get(job_name)

    if environment_value is None:
        raise _evidence_error()

    environment = DeploymentEnvironment(environment_value)
    lines = _normalized_trace_lines(body)

    deployed_count = _count_marker(lines, _DEPLOYED_MARKER)
    configuration_failed_count = _count_marker(
        lines,
        _CONFIGURATION_FAILED_MARKER,
    )
    previous_invalid_count = _count_marker(
        lines,
        _PREVIOUS_RELEASE_INVALID_MARKER,
    )
    failed_count = _count_marker(
        lines,
        _DEPLOYMENT_FAILED_MARKER,
    )

    primary_count = (
        deployed_count + configuration_failed_count + previous_invalid_count + failed_count
    )

    rollback_matches = [
        rollback
        for marker, rollback in _ROLLBACK_MARKERS.items()
        for _ in range(_count_marker(lines, marker))
    ]

    if primary_count != 1:
        raise _evidence_error()

    if deployed_count == 1:
        if rollback_matches:
            raise _evidence_error()

        return DeploymentEvidence(
            status=DeploymentResultStatus.DEPLOYED,
            environment=environment,
            target_commit_sha=event.sha,
            rollback=RollbackStatus.NOT_REQUIRED,
        )

    if configuration_failed_count == 1:
        if rollback_matches:
            raise _evidence_error()

        return DeploymentEvidence(
            status=DeploymentResultStatus.CONFIGURATION_FAILED,
            environment=environment,
            target_commit_sha=event.sha,
            rollback=RollbackStatus.NOT_ATTEMPTED,
        )

    if previous_invalid_count == 1:
        if rollback_matches:
            raise _evidence_error()

        return DeploymentEvidence(
            status=DeploymentResultStatus.PREVIOUS_RELEASE_INVALID,
            environment=environment,
            target_commit_sha=event.sha,
            rollback=RollbackStatus.NOT_ATTEMPTED,
        )

    if len(rollback_matches) != 1:
        raise _evidence_error()

    rollback = RollbackStatus(rollback_matches[0])

    if rollback is RollbackStatus.UNAVAILABLE:
        status = DeploymentResultStatus.DEPLOYMENT_FAILED
    elif rollback is RollbackStatus.SUCCEEDED:
        status = DeploymentResultStatus.DEPLOYMENT_FAILED_ROLLED_BACK
    elif rollback is RollbackStatus.FAILED:
        status = DeploymentResultStatus.ROLLBACK_FAILED
    else:
        raise _evidence_error()

    return DeploymentEvidence(
        status=status,
        environment=environment,
        target_commit_sha=event.sha,
        rollback=rollback,
    )


class GitLabDeploymentEvidenceClient:
    """Retrieve validated deployment evidence with read-only GitLab access."""

    def __init__(
        self,
        settings: GitLabSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def get_evidence(
        self,
        event: PipelineWebhookEvent,
    ) -> DeploymentEvidence | None:
        jobs = await self._load_pipeline_jobs(event)

        deployment_jobs = [job for job in jobs if job.get("name") in _DEPLOYMENT_JOB_ENVIRONMENTS]

        if not deployment_jobs:
            return None

        if len(deployment_jobs) != 1:
            raise _evidence_error()

        job = deployment_jobs[0]
        job_id = self._validate_job(
            job,
            event,
        )

        if job["status"] not in _TERMINAL_JOB_STATUSES:
            return None

        trace = await self._load_trace(job_id)

        return _parse_trace(
            trace,
            event=event,
            job_name=job["name"],
        )

    async def _load_pipeline_jobs(
        self,
        event: PipelineWebhookEvent,
    ) -> list[dict[str, Any]]:
        endpoint = (
            f"{self._settings.api_url}/projects/"
            f"{self._settings.project_id}/pipelines/"
            f"{event.pipeline_id}/jobs"
        )

        body = await self._request(
            endpoint,
            params={
                "include_retried": "false",
                "per_page": "100",
            },
            max_bytes=MAX_DEPLOYMENT_JOBS_BYTES,
        )

        try:
            payload = json.loads(body)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            raise _evidence_error() from exc

        if not isinstance(payload, list):
            raise _evidence_error()

        if not all(isinstance(job, dict) for job in payload):
            raise _evidence_error()

        return payload

    async def _load_trace(
        self,
        job_id: int,
    ) -> bytes:
        endpoint = (
            f"{self._settings.api_url}/projects/{self._settings.project_id}/jobs/{job_id}/trace"
        )

        return await self._request(
            endpoint,
            params=None,
            max_bytes=MAX_DEPLOYMENT_TRACE_BYTES,
        )

    async def _request(
        self,
        endpoint: str,
        *,
        params: dict[str, str] | None,
        max_bytes: int,
    ) -> bytes:
        headers = {
            "PRIVATE-TOKEN": self._settings.api_token.get_secret_value(),
        }

        try:
            async with httpx.AsyncClient(
                headers=headers,
                timeout=5.0,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream(
                    "GET",
                    endpoint,
                    params=params,
                ) as response:
                    if response.status_code != 200:
                        raise _evidence_error()

                    content_length = response.headers.get("content-length")

                    if content_length is not None:
                        try:
                            declared_length = int(content_length)
                        except ValueError as exc:
                            raise _evidence_error() from exc

                        if declared_length < 0 or declared_length > max_bytes:
                            raise _evidence_error()

                    body = bytearray()

                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > max_bytes:
                            raise _evidence_error()

                        body.extend(chunk)

                    return bytes(body)

        except DeploymentEvidenceError:
            raise
        except httpx.HTTPError as exc:
            raise _evidence_error() from exc

    def _validate_job(
        self,
        job: dict[str, Any],
        event: PipelineWebhookEvent,
    ) -> int:
        job_id = job.get("id")
        name = job.get("name")
        status = job.get("status")
        ref = job.get("ref")
        pipeline = job.get("pipeline")

        if not _is_positive_identifier(job_id):
            raise _evidence_error()

        if name not in _DEPLOYMENT_JOB_ENVIRONMENTS:
            raise _evidence_error()

        if not isinstance(status, str):
            raise _evidence_error()

        if ref != event.ref or ref != self._settings.default_ref:
            raise _evidence_error()

        if not isinstance(pipeline, dict):
            raise _evidence_error()

        if pipeline.get("id") != event.pipeline_id:
            raise _evidence_error()

        if pipeline.get("project_id") != self._settings.project_id:
            raise _evidence_error()

        if pipeline.get("ref") != event.ref:
            raise _evidence_error()

        if pipeline.get("sha") != event.sha:
            raise _evidence_error()

        return job_id

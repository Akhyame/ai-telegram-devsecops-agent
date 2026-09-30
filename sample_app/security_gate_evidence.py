"""Bounded read-only evidence for deterministic Security Gate blocks."""

import json
import re
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Any

import httpx

from bot.gitlab_config import GitLabSettings
from sample_app.webhook_events import PipelineEventStatus, PipelineWebhookEvent

MAX_SECURITY_GATE_RESPONSE_BYTES = 262_144
MAX_PIPELINE_JOBS = 100
SECURITY_GATE_JOB_NAME = "security_gate"

_MAX_IDENTIFIER = (2**63) - 1
_SHA_PATTERN = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_BLOCK_MARKER = re.compile(
    rb"Security gate decision: BLOCK "
    rb"\(([1-9][0-9]{0,18})/([1-9][0-9]{0,18}) blocking findings\)"
)
_REQUEST_TIMEOUT = httpx.Timeout(
    timeout=5.0,
    connect=5.0,
    read=5.0,
    write=5.0,
    pool=5.0,
)
_CONNECTION_LIMITS = httpx.Limits(
    max_connections=5,
    max_keepalive_connections=2,
)


class SecurityGateEvidenceError(RuntimeError):
    """Static failure while retrieving or validating gate evidence."""


@dataclass(frozen=True, slots=True)
class SecurityGateBlockEvidence:
    """Minimal validated counts from one deterministic gate block."""

    blocking_findings: int
    total_findings: int


def _evidence_error() -> SecurityGateEvidenceError:
    return SecurityGateEvidenceError("Security gate evidence is unavailable.")


def _is_positive_identifier(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_IDENTIFIER


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise _evidence_error()

        result[key] = value

    return result


async def _read_bounded(
    response: httpx.Response,
    *,
    maximum_bytes: int = MAX_SECURITY_GATE_RESPONSE_BYTES,
) -> bytes:
    content_length = response.headers.get("content-length")

    if content_length is not None:
        if not content_length.isascii() or not content_length.isdecimal():
            raise _evidence_error()

        if int(content_length) > maximum_bytes:
            raise _evidence_error()

    body = bytearray()

    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > maximum_bytes:
            raise _evidence_error()

        body.extend(chunk)

    return bytes(body)


class GitLabSecurityGateEvidenceClient:
    """Read one project-scoped Security Gate result without exposing logs."""

    def __init__(
        self,
        settings: GitLabSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def get_block_evidence(
        self,
        event: PipelineWebhookEvent,
    ) -> SecurityGateBlockEvidence | None:
        """Return evidence only for a validated deterministic block."""

        if event.status is not PipelineEventStatus.FAILED:
            return None

        if (
            event.ref != self._settings.default_ref
            or not _is_positive_identifier(event.pipeline_id)
            or _SHA_PATTERN.fullmatch(event.sha) is None
        ):
            raise _evidence_error()

        headers = {
            "Accept": "application/json",
            "PRIVATE-TOKEN": self._settings.api_token.get_secret_value(),
        }

        try:
            async with httpx.AsyncClient(
                base_url=f"{self._settings.api_url}/",
                headers=headers,
                timeout=_REQUEST_TIMEOUT,
                limits=_CONNECTION_LIMITS,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                job_id = await self._find_security_gate_job(
                    client,
                    event,
                )

                if job_id is None:
                    return None

                trace = await self._read_security_gate_trace(
                    client,
                    job_id,
                )
        except SecurityGateEvidenceError:
            raise
        except httpx.HTTPError as exc:
            raise _evidence_error() from exc

        matches = tuple(_BLOCK_MARKER.finditer(trace))

        if not matches:
            return None

        if len(matches) != 1:
            raise _evidence_error()

        blocking_findings = int(matches[0].group(1))
        total_findings = int(matches[0].group(2))

        if (
            blocking_findings > _MAX_IDENTIFIER
            or total_findings > _MAX_IDENTIFIER
            or blocking_findings > total_findings
        ):
            raise _evidence_error()

        return SecurityGateBlockEvidence(
            blocking_findings=blocking_findings,
            total_findings=total_findings,
        )

    async def _find_security_gate_job(
        self,
        client: httpx.AsyncClient,
        event: PipelineWebhookEvent,
    ) -> int | None:
        endpoint = f"projects/{self._settings.project_id}/pipelines/{event.pipeline_id}/jobs"

        async with client.stream(
            "GET",
            endpoint,
            params={
                "include_retried": "false",
                "per_page": MAX_PIPELINE_JOBS,
            },
        ) as response:
            if response.status_code != 200:
                raise _evidence_error()

            media_type = response.headers.get("content-type", "").partition(";")[0].strip().lower()

            if media_type != "application/json":
                raise _evidence_error()

            body = await _read_bounded(response)

        try:
            payload = json.loads(
                body,
                object_pairs_hook=_unique_object,
            )
        except (
            JSONDecodeError,
            UnicodeDecodeError,
            RecursionError,
            SecurityGateEvidenceError,
        ) as exc:
            raise _evidence_error() from exc

        if not isinstance(payload, list) or len(payload) > MAX_PIPELINE_JOBS:
            raise _evidence_error()

        matches: list[dict[str, Any]] = []

        for item in payload:
            if not isinstance(item, dict):
                raise _evidence_error()

            if item.get("name") == SECURITY_GATE_JOB_NAME:
                matches.append(item)

        if not matches:
            return None

        if len(matches) != 1:
            raise _evidence_error()

        job = matches[0]
        job_id = job.get("id")
        pipeline = job.get("pipeline")

        if (
            not _is_positive_identifier(job_id)
            or job.get("stage") != SECURITY_GATE_JOB_NAME
            or job.get("ref") != event.ref
            or not isinstance(pipeline, dict)
            or pipeline.get("id") != event.pipeline_id
            or pipeline.get("project_id") != self._settings.project_id
            or pipeline.get("ref") != event.ref
            or pipeline.get("sha") != event.sha
        ):
            raise _evidence_error()

        if job.get("status") != "failed":
            return None

        return job_id

    async def _read_security_gate_trace(
        self,
        client: httpx.AsyncClient,
        job_id: int,
    ) -> bytes:
        endpoint = f"projects/{self._settings.project_id}/jobs/{job_id}/trace"

        async with client.stream(
            "GET",
            endpoint,
            headers={"Accept": "text/plain"},
        ) as response:
            if response.status_code != 200 or response.is_redirect:
                raise _evidence_error()

            return await _read_bounded(response)

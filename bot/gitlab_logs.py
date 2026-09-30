"""Bounded read-only retrieval and redaction of GitLab job logs."""

import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

from bot.gitlab_client import (
    MAX_GITLAB_RESPONSE_BYTES,
    GitLabClient,
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_config import GitLabSettings

MAX_PIPELINE_JOBS = 20
MAX_GITLAB_TRACE_BYTES = 262_144
MAX_LOG_LINES = 40
MAX_LOG_OUTPUT_CHARACTERS = 3_000

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
_MAX_IDENTIFIER = (2**63) - 1
_JOB_NAME_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:/ -]{0,99}\Z")
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])")
_URL_CREDENTIAL_PATTERN = re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@")
_AUTHORIZATION_PATTERN = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_JWT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    r"(?![A-Za-z0-9_-])"
)
_TELEGRAM_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"[1-9][0-9]{0,19}:[A-Za-z0-9_-]{20,200}"
    r"(?![A-Za-z0-9_-])"
)
_GITLAB_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"gl(?:pat|ptt|cbt|rt|soat)-[A-Za-z0-9_.-]{20,200}"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \b(?:
        authorization
        | ci_job_token
        | gitlab_api_token
        | private-token
        | telegram_bot_token
        | api[_-]?key
        | password
        | secret
        | token
    )\b
    \s*[:=]\s*
    (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s\r\n]+)
    """
)


@dataclass(frozen=True, slots=True)
class JobSummary:
    """Validated subset of one GitLab pipeline job."""

    job_id: int
    name: str
    status: PipelineStatus
    pipeline_id: int


@dataclass(frozen=True, slots=True)
class JobLogSummary:
    """Sanitized and size-limited trace for one validated job."""

    job: JobSummary
    text: str
    truncated: bool


class GitLabJobLogClient:
    """Retrieve one bounded job trace from the latest configured pipeline."""

    def __init__(
        self,
        settings: GitLabSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def get_latest_job_log(self) -> JobLogSummary:
        """Return a redacted trace from the latest failed or newest job."""

        pipeline = await GitLabClient(
            self._settings,
            transport=self._transport,
        ).get_latest_pipeline()
        jobs = await self._get_pipeline_jobs(pipeline)
        job = self._select_job(jobs)
        trace = await self._get_job_trace(job.job_id)
        text, truncated = self._sanitize_trace(trace)

        return JobLogSummary(
            job=job,
            text=text,
            truncated=truncated,
        )

    async def get_latest_failed_job_log(self) -> JobLogSummary:
        """Return a sanitized trace from the latest failed pipeline."""

        pipeline = await self._get_latest_failed_pipeline()
        jobs = await self._get_pipeline_jobs(pipeline)
        job = self._select_failed_job(jobs)
        trace = await self._get_job_trace(job.job_id)
        text, truncated = self._sanitize_trace(trace)

        return JobLogSummary(
            job=job,
            text=text,
            truncated=truncated,
        )

    async def _get_latest_failed_pipeline(
        self,
    ) -> PipelineSummary:
        endpoint = f"projects/{self._settings.project_id}/pipelines"
        body = await self._request_bounded(
            endpoint,
            params={
                "ref": self._settings.default_ref,
                "status": PipelineStatus.FAILED.value,
                "order_by": "id",
                "sort": "desc",
                "page": "1",
                "per_page": "1",
            },
            accept="application/json",
            allowed_content_types=frozenset(
                {
                    "application/json",
                }
            ),
            max_bytes=MAX_GITLAB_RESPONSE_BYTES,
        )
        payload = self._decode_json(body)

        if not isinstance(payload, list):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not payload:
            raise GitLabClientError(GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING)

        if len(payload) != 1:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        pipeline = GitLabClient(
            self._settings,
            transport=self._transport,
        )._parse_pipeline(payload[0])

        if pipeline.status is not PipelineStatus.FAILED:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return pipeline

    async def _get_pipeline_jobs(
        self,
        pipeline: PipelineSummary,
    ) -> tuple[JobSummary, ...]:
        endpoint = f"projects/{self._settings.project_id}/pipelines/{pipeline.pipeline_id}/jobs"
        body = await self._request_bounded(
            endpoint,
            params={
                "include_retried": "false",
                "page": "1",
                "per_page": str(MAX_PIPELINE_JOBS),
            },
            accept="application/json",
            allowed_content_types=frozenset(
                {
                    "application/json",
                }
            ),
            max_bytes=MAX_GITLAB_RESPONSE_BYTES,
        )
        payload = self._decode_json(body)

        return self._parse_jobs(payload, pipeline)

    async def _get_job_trace(
        self,
        job_id: int,
    ) -> bytes:
        endpoint = f"projects/{self._settings.project_id}/jobs/{job_id}/trace"

        return await self._request_bounded(
            endpoint,
            params=None,
            accept="text/plain",
            allowed_content_types=frozenset(
                {
                    "application/octet-stream",
                    "text/plain",
                }
            ),
            max_bytes=MAX_GITLAB_TRACE_BYTES,
        )

    async def _request_bounded(
        self,
        endpoint: str,
        *,
        params: dict[str, str] | None,
        accept: str,
        allowed_content_types: frozenset[str],
        max_bytes: int,
    ) -> bytes:
        headers = {
            "Accept": accept,
            "PRIVATE-TOKEN": (self._settings.api_token.get_secret_value()),
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
                async with client.stream(
                    "GET",
                    endpoint,
                    params=params,
                ) as response:
                    self._raise_for_status(response.status_code)

                    content_type = (
                        response.headers.get(
                            "content-type",
                            "",
                        )
                        .partition(";")[0]
                        .strip()
                        .lower()
                    )

                    if content_type not in allowed_content_types:
                        raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

                    return await self._read_bounded_body(
                        response,
                        max_bytes=max_bytes,
                    )

        except GitLabClientError:
            raise
        except httpx.TimeoutException as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc
        except httpx.RequestError as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc

    @staticmethod
    def _raise_for_status(
        status_code: int,
    ) -> None:
        if status_code == 200:
            return

        if status_code == 401:
            kind = GitLabErrorKind.AUTHENTICATION
        elif status_code in {403, 404}:
            kind = GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING
        elif status_code == 429:
            kind = GitLabErrorKind.RATE_LIMITED
        elif 500 <= status_code <= 599:
            kind = GitLabErrorKind.UPSTREAM
        else:
            kind = GitLabErrorKind.INVALID_RESPONSE

        raise GitLabClientError(kind)

    @staticmethod
    async def _read_bounded_body(
        response: httpx.Response,
        *,
        max_bytes: int,
    ) -> bytes:
        content_length = response.headers.get("content-length")

        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

            if declared_length < 0 or declared_length > max_bytes:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        body = bytearray()

        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > max_bytes:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

            body.extend(chunk)

        return bytes(body)

    @staticmethod
    def _decode_json(
        body: bytes,
    ) -> Any:
        try:
            return json.loads(body)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

    def _parse_jobs(
        self,
        payload: Any,
        pipeline: PipelineSummary,
    ) -> tuple[JobSummary, ...]:
        if not isinstance(payload, list):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not payload:
            raise GitLabClientError(GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING)

        if len(payload) > MAX_PIPELINE_JOBS:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        jobs = tuple(self._parse_job(item, pipeline) for item in payload)

        if len({job.job_id for job in jobs}) != len(jobs):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return jobs

    def _parse_job(
        self,
        payload: Any,
        pipeline: PipelineSummary,
    ) -> JobSummary:
        if not isinstance(payload, dict):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        job_id = payload.get("id")
        name = payload.get("name")
        raw_status = payload.get("status")
        ref = payload.get("ref")
        raw_pipeline = payload.get("pipeline")

        if not self._is_positive_identifier(job_id):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not isinstance(name, str) or _JOB_NAME_PATTERN.fullmatch(name) is None:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not isinstance(raw_status, str):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        try:
            status = PipelineStatus(raw_status)
        except ValueError as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

        if ref != pipeline.ref:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not isinstance(raw_pipeline, dict):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if raw_pipeline.get("id") != pipeline.pipeline_id:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if raw_pipeline.get("project_id") != self._settings.project_id:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if raw_pipeline.get("ref") != pipeline.ref:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if raw_pipeline.get("sha") != pipeline.sha:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return JobSummary(
            job_id=job_id,
            name=name,
            status=status,
            pipeline_id=pipeline.pipeline_id,
        )

    @staticmethod
    def _select_job(
        jobs: tuple[JobSummary, ...],
    ) -> JobSummary:
        failed_jobs = tuple(job for job in jobs if job.status is PipelineStatus.FAILED)

        return max(
            failed_jobs or jobs,
            key=lambda job: job.job_id,
        )

    @staticmethod
    def _select_failed_job(
        jobs: tuple[JobSummary, ...],
    ) -> JobSummary:
        failed_jobs = tuple(job for job in jobs if job.status is PipelineStatus.FAILED)

        if not failed_jobs:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return max(
            failed_jobs,
            key=lambda job: job.job_id,
        )

    def _sanitize_trace(
        self,
        trace: bytes,
    ) -> tuple[str, bool]:
        text = trace.decode(
            "utf-8",
            errors="replace",
        )
        text = _ANSI_ESCAPE_PATTERN.sub("", text)
        text = text.replace(
            "\r\n",
            "\n",
        ).replace(
            "\r",
            "\n",
        )
        text = "".join(
            character
            for character in text
            if (character in {"\n", "\t"} or character.isprintable())
        )

        real_token = self._settings.api_token.get_secret_value()
        text = text.replace(
            real_token,
            "[REDACTED]",
        )
        text = _URL_CREDENTIAL_PATTERN.sub(
            r"\1[REDACTED]@",
            text,
        )
        text = _AUTHORIZATION_PATTERN.sub(
            "[REDACTED]",
            text,
        )
        text = _JWT_PATTERN.sub(
            "[REDACTED]",
            text,
        )
        text = _TELEGRAM_TOKEN_PATTERN.sub(
            "[REDACTED]",
            text,
        )
        text = _GITLAB_TOKEN_PATTERN.sub(
            "[REDACTED]",
            text,
        )
        text = _SECRET_ASSIGNMENT_PATTERN.sub(
            "[REDACTED]",
            text,
        )

        lines = text.splitlines()
        truncated = len(lines) > MAX_LOG_LINES
        rendered = "\n".join(lines[-MAX_LOG_LINES:]).strip()

        if len(rendered) > MAX_LOG_OUTPUT_CHARACTERS:
            rendered = rendered[-MAX_LOG_OUTPUT_CHARACTERS:]
            first_newline = rendered.find("\n")

            if first_newline >= 0:
                rendered = rendered[first_newline + 1 :]

            rendered = rendered.strip()
            truncated = True

        if not rendered:
            rendered = "(no log output)"

        return rendered, truncated

    @staticmethod
    def _is_positive_identifier(
        value: object,
    ) -> bool:
        return (
            isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_IDENTIFIER
        )

"""Bounded and read-only GitLab pipeline status client."""

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import httpx

from bot.gitlab_config import GitLabSettings

MAX_GITLAB_RESPONSE_BYTES = 65_536

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
_SHA_PATTERN = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_IDENTIFIER = (2**63) - 1


class PipelineStatus(StrEnum):
    """Pipeline states documented by the GitLab Pipelines API."""

    CREATED = "created"
    WAITING_FOR_RESOURCE = "waiting_for_resource"
    PREPARING = "preparing"
    WAITING_FOR_CALLBACK = "waiting_for_callback"
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELING = "canceling"
    CANCELED = "canceled"
    SKIPPED = "skipped"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class GitLabErrorKind(StrEnum):
    """Controlled categories for GitLab client failures."""

    AUTHENTICATION = "authentication"
    ACCESS_OR_PIPELINE_MISSING = "access_or_pipeline_missing"
    PROJECT_NOT_FOUND = "project_not_found"
    RATE_LIMITED = "rate_limited"
    UPSTREAM = "upstream"
    ACTION_NOT_ALLOWED = "action_not_allowed"
    INVALID_RESPONSE = "invalid_response"
    NETWORK = "network"


class GitLabClientError(RuntimeError):
    """Static, non-sensitive GitLab client failure."""

    def __init__(
        self,
        kind: GitLabErrorKind,
    ) -> None:
        super().__init__("GitLab request failed.")
        self.kind = kind


@dataclass(frozen=True, slots=True)
class PipelineSummary:
    """Validated subset of a GitLab pipeline response."""

    pipeline_id: int
    status: PipelineStatus
    ref: str
    sha: str


class GitLabClient:
    """Fetch validated pipeline state through one read-only endpoint."""

    def __init__(
        self,
        settings: GitLabSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def get_latest_pipeline(self) -> PipelineSummary:
        """Return the latest validated pipeline for the configured ref."""

        endpoint = f"projects/{self._settings.project_id}/pipelines/latest"
        headers = {
            "Accept": "application/json",
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
                    params={
                        "ref": self._settings.default_ref,
                    },
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

                    if content_type != "application/json":
                        raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

                    body = await self._read_bounded_body(response)

        except GitLabClientError:
            raise
        except httpx.TimeoutException as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc
        except httpx.RequestError as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc

        try:
            payload = json.loads(body)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

        return self._parse_pipeline(payload)

    @staticmethod
    def _raise_for_status(
        status_code: int,
    ) -> None:
        if status_code == 200:
            return

        if status_code == 401:
            kind = GitLabErrorKind.AUTHENTICATION
        elif status_code == 403:
            kind = GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING
        elif status_code == 404:
            kind = GitLabErrorKind.PROJECT_NOT_FOUND
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
    ) -> bytes:
        content_length = response.headers.get("content-length")

        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

            if declared_length < 0 or declared_length > MAX_GITLAB_RESPONSE_BYTES:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        body = bytearray()

        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > MAX_GITLAB_RESPONSE_BYTES:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

            body.extend(chunk)

        return bytes(body)

    def _parse_pipeline(
        self,
        payload: Any,
    ) -> PipelineSummary:
        if not isinstance(payload, dict):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        pipeline_id = payload.get("id")
        project_id = payload.get("project_id")
        raw_status = payload.get("status")
        ref = payload.get("ref")
        sha = payload.get("sha")

        if not self._is_positive_identifier(pipeline_id):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not self._is_positive_identifier(project_id) or project_id != self._settings.project_id:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not isinstance(raw_status, str):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        try:
            status = PipelineStatus(raw_status)
        except ValueError as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

        if not isinstance(ref, str) or ref != self._settings.default_ref:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not isinstance(sha, str) or _SHA_PATTERN.fullmatch(sha) is None:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return PipelineSummary(
            pipeline_id=pipeline_id,
            status=status,
            ref=ref,
            sha=sha,
        )

    @staticmethod
    def _is_positive_identifier(
        value: object,
    ) -> bool:
        return (
            isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_IDENTIFIER
        )

"""Bounded GitLab client for controlled pipeline write actions."""

import json
import re
from typing import Any

import httpx

from bot.gitlab_client import (
    MAX_GITLAB_RESPONSE_BYTES,
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_write_config import GitLabWriteSettings
from deployment.models import DeploymentEnvironment

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

_CANCELLABLE_STATUSES = frozenset(
    {
        PipelineStatus.CREATED,
        PipelineStatus.WAITING_FOR_RESOURCE,
        PipelineStatus.PREPARING,
        PipelineStatus.WAITING_FOR_CALLBACK,
        PipelineStatus.PENDING,
        PipelineStatus.RUNNING,
        PipelineStatus.MANUAL,
        PipelineStatus.SCHEDULED,
    }
)
_RETRYABLE_STATUSES = frozenset(
    {
        PipelineStatus.FAILED,
        PipelineStatus.CANCELED,
    }
)


class GitLabWriteClient:
    """Perform fixed-project pipeline actions through validated boundaries."""

    def __init__(
        self,
        settings: GitLabWriteSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def run_pipeline(self) -> PipelineSummary:
        """Launch and return one validated pipeline for the allowed ref."""

        endpoint = f"projects/{self._settings.project_id}/pipeline"

        return await self._request_pipeline(
            method="POST",
            endpoint=endpoint,
            expected_status_code=201,
            json_body={
                "ref": self._settings.allowed_ref,
            },
        )

    async def run_security_scan(self) -> PipelineSummary:
        """Launch the fixed security-only pipeline profile."""

        endpoint = f"projects/{self._settings.project_id}/pipeline"

        return await self._request_pipeline(
            method="POST",
            endpoint=endpoint,
            expected_status_code=201,
            json_body={
                "ref": self._settings.allowed_ref,
                "inputs": {
                    "pipeline_profile": "security",
                },
            },
        )

    async def run_deployment(
        self,
        environment: DeploymentEnvironment,
    ) -> PipelineSummary:
        """Launch the single Telegram-authorized staging deployment."""

        if not isinstance(environment, DeploymentEnvironment):
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        if environment != DeploymentEnvironment.STAGING:
            raise GitLabClientError(
                GitLabErrorKind.ACTION_NOT_ALLOWED,
            )

        endpoint = f"projects/{self._settings.project_id}/pipeline"

        return await self._request_pipeline(
            method="POST",
            endpoint=endpoint,
            expected_status_code=201,
            json_body={
                "ref": self._settings.allowed_ref,
                "inputs": {
                    "pipeline_profile": "full",
                    "deployment_environment": environment.value,
                },
            },
        )

    async def cancel_pipeline(
        self,
        pipeline_id: int,
    ) -> PipelineSummary:
        """Cancel one validated active pipeline on the allowed ref."""

        return await self._act_on_pipeline(
            pipeline_id=pipeline_id,
            action="cancel",
            allowed_statuses=_CANCELLABLE_STATUSES,
        )

    async def retry_pipeline(
        self,
        pipeline_id: int,
    ) -> PipelineSummary:
        """Retry one validated failed or canceled pipeline on the allowed ref."""

        return await self._act_on_pipeline(
            pipeline_id=pipeline_id,
            action="retry",
            allowed_statuses=_RETRYABLE_STATUSES,
        )

    async def _act_on_pipeline(
        self,
        *,
        pipeline_id: int,
        action: str,
        allowed_statuses: frozenset[PipelineStatus],
    ) -> PipelineSummary:
        validated_pipeline_id = self._validate_pipeline_id(pipeline_id)
        endpoint = f"projects/{self._settings.project_id}/pipelines/{validated_pipeline_id}"

        current = await self._request_pipeline(
            method="GET",
            endpoint=endpoint,
            expected_status_code=200,
            pipeline_scoped=True,
        )

        if current.pipeline_id != validated_pipeline_id:
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        if current.status not in allowed_statuses:
            raise GitLabClientError(
                GitLabErrorKind.ACTION_NOT_ALLOWED,
            )

        result = await self._request_pipeline(
            method="POST",
            endpoint=f"{endpoint}/{action}",
            expected_status_code=200,
            pipeline_scoped=True,
        )

        if result.pipeline_id != validated_pipeline_id:
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        return result

    async def _request_pipeline(
        self,
        *,
        method: str,
        endpoint: str,
        expected_status_code: int,
        json_body: dict[str, Any] | None = None,
        pipeline_scoped: bool = False,
    ) -> PipelineSummary:
        headers = {
            "Accept": "application/json",
            "PRIVATE-TOKEN": self._settings.api_token.get_secret_value(),
        }
        request_arguments: dict[str, Any] = {}

        if json_body is not None:
            request_arguments["json"] = json_body

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
                    method,
                    endpoint,
                    **request_arguments,
                ) as response:
                    self._raise_for_status(
                        response.status_code,
                        expected_status_code=expected_status_code,
                        pipeline_scoped=pipeline_scoped,
                    )

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
                        raise GitLabClientError(
                            GitLabErrorKind.INVALID_RESPONSE,
                        )

                    body = await self._read_bounded_body(response)

        except GitLabClientError:
            raise
        except httpx.TimeoutException as exc:
            raise GitLabClientError(
                GitLabErrorKind.NETWORK,
            ) from exc
        except httpx.RequestError as exc:
            raise GitLabClientError(
                GitLabErrorKind.NETWORK,
            ) from exc

        try:
            payload = json.loads(body)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            ) from exc

        return self._parse_pipeline(payload)

    @staticmethod
    def _raise_for_status(
        status_code: int,
        *,
        expected_status_code: int,
        pipeline_scoped: bool,
    ) -> None:
        if status_code == expected_status_code:
            return

        if status_code == 401:
            kind = GitLabErrorKind.AUTHENTICATION
        elif status_code == 403:
            kind = GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING
        elif status_code == 404 and pipeline_scoped:
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
            if not content_length.isascii() or not content_length.isdecimal():
                raise GitLabClientError(
                    GitLabErrorKind.INVALID_RESPONSE,
                )

            if int(content_length) > MAX_GITLAB_RESPONSE_BYTES:
                raise GitLabClientError(
                    GitLabErrorKind.INVALID_RESPONSE,
                )

        body = bytearray()

        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > MAX_GITLAB_RESPONSE_BYTES:
                raise GitLabClientError(
                    GitLabErrorKind.INVALID_RESPONSE,
                )

            body.extend(chunk)

        return bytes(body)

    def _parse_pipeline(
        self,
        payload: Any,
    ) -> PipelineSummary:
        if not isinstance(payload, dict):
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        pipeline_id = payload.get("id")
        project_id = payload.get("project_id")
        raw_status = payload.get("status")
        ref = payload.get("ref")
        sha = payload.get("sha")

        if not self._is_positive_identifier(pipeline_id):
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        if not self._is_positive_identifier(project_id) or project_id != self._settings.project_id:
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        if not isinstance(raw_status, str):
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        try:
            status = PipelineStatus(raw_status)
        except ValueError as exc:
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            ) from exc

        if not isinstance(ref, str) or ref != self._settings.allowed_ref:
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        if not isinstance(sha, str) or _SHA_PATTERN.fullmatch(sha) is None:
            raise GitLabClientError(
                GitLabErrorKind.INVALID_RESPONSE,
            )

        return PipelineSummary(
            pipeline_id=pipeline_id,
            status=status,
            ref=ref,
            sha=sha,
        )

    @classmethod
    def _validate_pipeline_id(
        cls,
        value: object,
    ) -> int:
        if not cls._is_positive_identifier(value):
            raise GitLabClientError(
                GitLabErrorKind.ACTION_NOT_ALLOWED,
            )

        return value

    @staticmethod
    def _is_positive_identifier(
        value: object,
    ) -> bool:
        return (
            isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_IDENTIFIER
        )

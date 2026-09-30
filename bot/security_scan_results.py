"""Read and strictly normalize one GitLab Security Gate result."""

import json
import re
from typing import Any

import httpx
from pydantic import ValidationError

from agent.security_models import (
    MAX_BLOCKING_DETAILS,
    NormalizedSecurityScan,
    SecurityFindingSummary,
    SecurityScanDecision,
    SecurityScanner,
    SecuritySeverity,
)
from bot.gitlab_client import (
    MAX_GITLAB_RESPONSE_BYTES,
    GitLabClient,
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
)
from bot.gitlab_config import GitLabSettings

MAX_SECURITY_GATE_RESULT_BYTES = 32_768
MAX_PIPELINE_JOBS = 100
SECURITY_GATE_JOB_NAME = "security_gate"

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
_REDIRECT_STATUSES = frozenset(
    {
        301,
        302,
        303,
        307,
        308,
    }
)
_ARTIFACT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "application/octet-stream",
        "binary/octet-stream",
        "text/plain",
    }
)
_TERMINAL_PIPELINE_STATUSES = frozenset(
    {
        PipelineStatus.SUCCESS,
        PipelineStatus.FAILED,
    }
)
_SOURCE_FRAGMENT = (
    r"(?:gitleaks|pip-audit|semgrep|"
    r"trivy-vulnerability|trivy-misconfiguration)"
)
_RULE_ID_FRAGMENT = r"[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,127}"
_BLOCKED_REASON_PATTERN = re.compile(
    rf"\A(?P<source>{_SOURCE_FRAGMENT}):"
    rf"(?P<rule_id>{_RULE_ID_FRAGMENT}) "
    rf"has blocked severity "
    rf"(?P<severity>info|low|medium|high|critical)\Z"
)
_UNKNOWN_REASON_PATTERN = re.compile(
    rf"\A(?P<source>{_SOURCE_FRAGMENT}):"
    rf"(?P<rule_id>{_RULE_ID_FRAGMENT}) "
    rf"has an unknown severity\Z"
)
_MAX_IDENTIFIER = (2**63) - 1


class _DuplicateKeyError(ValueError):
    """Internal marker for duplicate JSON object keys."""


def _unique_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError

        result[key] = value

    return result


def _load_unique_json(
    body: bytes,
) -> Any:
    try:
        text = body.decode(
            "utf-8",
            errors="strict",
        )
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateKeyError,
    ) as exc:
        raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc


class GitLabSecurityScanResultClient:
    """Retrieve only the bounded result of the latest Security Gate."""

    def __init__(
        self,
        settings: GitLabSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def get_latest_security_scan(
        self,
    ) -> NormalizedSecurityScan:
        """Return a validated result without exposing raw scanner reports."""

        pipeline = await GitLabClient(
            self._settings,
            transport=self._transport,
        ).get_latest_pipeline()

        if pipeline.status not in _TERMINAL_PIPELINE_STATUSES:
            raise GitLabClientError(GitLabErrorKind.ACTION_NOT_ALLOWED)

        job_id, job_status = await self._get_security_gate_job(
            pipeline.pipeline_id,
            pipeline.status,
        )
        artifact = await self._get_security_gate_artifact(
            job_id,
        )
        scan = self._parse_gate_result(artifact)

        if job_status is PipelineStatus.SUCCESS and scan.decision is not SecurityScanDecision.ALLOW:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if job_status is PipelineStatus.FAILED and scan.decision is not SecurityScanDecision.BLOCK:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return scan

    async def _get_security_gate_job(
        self,
        pipeline_id: int,
        pipeline_status: PipelineStatus,
    ) -> tuple[int, PipelineStatus]:
        endpoint = f"projects/{self._settings.project_id}/pipelines/{pipeline_id}/jobs"

        try:
            async with httpx.AsyncClient(
                base_url=f"{self._settings.api_url}/",
                headers={
                    "Accept": "application/json",
                    "PRIVATE-TOKEN": (self._settings.api_token.get_secret_value()),
                },
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
                        "include_retried": "false",
                        "per_page": str(MAX_PIPELINE_JOBS),
                    },
                ) as response:
                    self._raise_for_status(response.status_code)

                    if self._media_type(response) != "application/json":
                        raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

                    if response.headers.get(
                        "x-next-page",
                        "",
                    ).strip():
                        raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

                    body = await self._read_bounded_body(
                        response,
                        MAX_GITLAB_RESPONSE_BYTES,
                    )

        except GitLabClientError:
            raise
        except httpx.TimeoutException as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc
        except httpx.RequestError as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc

        return self._parse_security_gate_job(
            _load_unique_json(body),
            pipeline_id,
            pipeline_status,
        )

    async def _get_security_gate_artifact(
        self,
        job_id: int,
    ) -> bytes:
        endpoint = (
            f"projects/{self._settings.project_id}/jobs/"
            f"{job_id}/artifacts/security-gate-result.json"
        )
        redirect_url: httpx.URL | None = None

        try:
            async with httpx.AsyncClient(
                base_url=f"{self._settings.api_url}/",
                headers={
                    "Accept": ("application/json, application/octet-stream, text/plain"),
                    "PRIVATE-TOKEN": (self._settings.api_token.get_secret_value()),
                },
                timeout=_REQUEST_TIMEOUT,
                limits=_CONNECTION_LIMITS,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream(
                    "GET",
                    endpoint,
                ) as response:
                    if response.status_code in _REDIRECT_STATUSES:
                        redirect_url = self._validate_redirect(response.headers.get("location"))
                    else:
                        self._raise_for_status(response.status_code)
                        self._validate_artifact_media_type(response)
                        return await self._read_bounded_body(
                            response,
                            MAX_SECURITY_GATE_RESULT_BYTES,
                        )

            if redirect_url is None:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

            return await self._download_redirected_artifact(redirect_url)

        except GitLabClientError:
            raise
        except httpx.TimeoutException as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc
        except httpx.RequestError as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc

    async def _download_redirected_artifact(
        self,
        redirect_url: httpx.URL,
    ) -> bytes:
        async with httpx.AsyncClient(
            headers={
                "Accept": ("application/json, application/octet-stream, text/plain"),
            },
            timeout=_REQUEST_TIMEOUT,
            limits=_CONNECTION_LIMITS,
            follow_redirects=True,
            max_redirects=5,
            trust_env=False,
            transport=self._transport,
        ) as client:
            async with client.stream(
                "GET",
                redirect_url,
            ) as response:
                self._validate_final_download_url(response.url)
                self._raise_for_status(response.status_code)
                self._validate_artifact_media_type(response)

                return await self._read_bounded_body(
                    response,
                    MAX_SECURITY_GATE_RESULT_BYTES,
                )

    def _parse_security_gate_job(
        self,
        payload: Any,
        pipeline_id: int,
        pipeline_status: PipelineStatus,
    ) -> tuple[int, PipelineStatus]:
        if not isinstance(payload, list) or not 1 <= len(payload) <= MAX_PIPELINE_JOBS:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        matches = [
            item
            for item in payload
            if isinstance(item, dict) and item.get("name") == SECURITY_GATE_JOB_NAME
        ]

        if len(matches) != 1:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        job = matches[0]
        job_id = job.get("id")
        raw_status = job.get("status")
        stage = job.get("stage")
        ref = job.get("ref")
        nested_pipeline = job.get("pipeline")

        if not self._is_positive_identifier(job_id):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if (
            stage != SECURITY_GATE_JOB_NAME
            or ref != self._settings.default_ref
            or not isinstance(nested_pipeline, dict)
            or nested_pipeline.get("id") != pipeline_id
        ):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        if not isinstance(raw_status, str):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        try:
            job_status = PipelineStatus(raw_status)
        except ValueError as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

        if job_status not in _TERMINAL_PIPELINE_STATUSES or job_status is not pipeline_status:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return job_id, job_status

    @classmethod
    def _parse_gate_result(
        cls,
        body: bytes,
    ) -> NormalizedSecurityScan:
        payload = _load_unique_json(body)
        expected_keys = {
            "decision",
            "total_findings",
            "blocking_findings",
            "reasons",
        }

        if not isinstance(payload, dict) or set(payload) != expected_keys:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        raw_decision = payload["decision"]
        total_findings = payload["total_findings"]
        blocking_findings = payload["blocking_findings"]
        reasons = payload["reasons"]

        if not isinstance(raw_decision, str):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        try:
            decision = SecurityScanDecision(raw_decision)
        except ValueError as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

        if (
            not cls._is_count(
                total_findings,
                maximum=1000,
            )
            or not cls._is_count(
                blocking_findings,
                maximum=100,
            )
            or not isinstance(reasons, list)
            or len(reasons) != blocking_findings
        ):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        details = tuple(cls._parse_reason(reason) for reason in reasons)

        try:
            return NormalizedSecurityScan(
                decision=decision,
                total_findings=total_findings,
                blocking_findings=blocking_findings,
                blocking_details=details[:MAX_BLOCKING_DETAILS],
                details_truncated=(blocking_findings > MAX_BLOCKING_DETAILS),
            )
        except ValidationError as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

    @staticmethod
    def _parse_reason(
        reason: object,
    ) -> SecurityFindingSummary:
        if not isinstance(reason, str):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        match = _BLOCKED_REASON_PATTERN.fullmatch(reason)

        if match is not None:
            source = SecurityScanner(match.group("source"))
            severity = SecuritySeverity(match.group("severity"))
            rule_id = match.group("rule_id")
        else:
            match = _UNKNOWN_REASON_PATTERN.fullmatch(reason)

            if match is None:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

            source = SecurityScanner(match.group("source"))
            severity = SecuritySeverity.UNKNOWN
            rule_id = match.group("rule_id")

        try:
            return SecurityFindingSummary(
                source=source,
                rule_id=rule_id,
                severity=severity,
            )
        except ValidationError as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

    @staticmethod
    def _validate_redirect(
        location: str | None,
    ) -> httpx.URL:
        if not location:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        try:
            url = httpx.URL(location)
        except Exception as exc:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

        host = url.host.lower() if isinstance(url.host, str) else ""

        if (
            url.scheme != "https"
            or not host
            or url.port
            not in (
                None,
                443,
            )
            or not (
                host == "cdn.artifacts.gitlab-static.net"
                or host.endswith(".artifacts.gitlab-static.net")
            )
        ):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        return url

    @staticmethod
    def _validate_final_download_url(
        url: httpx.URL,
    ) -> None:
        if (
            url.scheme != "https"
            or not url.host
            or url.port
            not in (
                None,
                443,
            )
        ):
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

    @staticmethod
    def _validate_artifact_media_type(
        response: httpx.Response,
    ) -> None:
        if GitLabSecurityScanResultClient._media_type(response) not in _ARTIFACT_MEDIA_TYPES:
            raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

    @staticmethod
    def _media_type(
        response: httpx.Response,
    ) -> str:
        return (
            response.headers.get(
                "content-type",
                "",
            )
            .partition(";")[0]
            .strip()
            .lower()
        )

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
        maximum_bytes: int,
    ) -> bytes:
        content_length = response.headers.get("content-length")

        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE) from exc

            if declared_length < 0 or declared_length > maximum_bytes:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

        body = bytearray()

        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > maximum_bytes:
                raise GitLabClientError(GitLabErrorKind.INVALID_RESPONSE)

            body.extend(chunk)

        return bytes(body)

    @staticmethod
    def _is_positive_identifier(
        value: object,
    ) -> bool:
        return (
            isinstance(value, int) and not isinstance(value, bool) and 0 < value <= _MAX_IDENTIFIER
        )

    @staticmethod
    def _is_count(
        value: object,
        *,
        maximum: int,
    ) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum

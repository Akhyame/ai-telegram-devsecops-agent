"""Offline tests for bounded and redacted GitLab job logs."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from bot.gitlab_client import (
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
)
from bot.gitlab_config import GitLabSettings
from bot.gitlab_logs import (
    MAX_GITLAB_TRACE_BYTES,
    MAX_LOG_LINES,
    MAX_LOG_OUTPUT_CHARACTERS,
    MAX_PIPELINE_JOBS,
    GitLabJobLogClient,
    JobLogSummary,
    JobSummary,
)

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = 123456
_PIPELINE_ID = 987654
_DEFAULT_REF = "main"
_VALID_SHA = "a" * 40
_DEFAULT_PAYLOAD = object()


def _valid_token() -> str:
    return "".join(
        (
            "gl",
            "pat-",
            "A" * 24,
            ".",
            "B" * 24,
        )
    )


def _settings() -> GitLabSettings:
    return GitLabSettings(
        GITLAB_API_URL=_API_URL,
        GITLAB_PROJECT_ID=str(_PROJECT_ID),
        GITLAB_DEFAULT_REF=_DEFAULT_REF,
        GITLAB_API_TOKEN=_valid_token(),
    )


def _pipeline_payload() -> dict[str, Any]:
    return {
        "id": _PIPELINE_ID,
        "project_id": _PROJECT_ID,
        "status": "success",
        "ref": _DEFAULT_REF,
        "sha": _VALID_SHA,
    }


def _job_payload(
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": 222,
        "name": "security_scan",
        "status": "success",
        "ref": _DEFAULT_REF,
        "pipeline": {
            "id": _PIPELINE_ID,
            "project_id": _PROJECT_ID,
            "ref": _DEFAULT_REF,
            "sha": _VALID_SHA,
        },
        "user": {
            "name": "untrusted-user-content",
        },
    }
    payload.update(overrides)

    return payload


def _client(
    handler: Callable[
        [httpx.Request],
        httpx.Response,
    ],
) -> GitLabJobLogClient:
    return GitLabJobLogClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )


def _latest_log(
    client: GitLabJobLogClient,
) -> JobLogSummary:
    return asyncio.run(client.get_latest_job_log())


def _standard_handler(
    *,
    jobs_payload: object = _DEFAULT_PAYLOAD,
    trace: bytes = b"trace",
    trace_status: int = 200,
    trace_content_type: str = "text/plain",
) -> Callable[
    [httpx.Request],
    httpx.Response,
]:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith("/pipelines/latest"):
            return httpx.Response(
                200,
                json=_pipeline_payload(),
            )

        if request.url.path.endswith("/jobs"):
            payload = [_job_payload()] if jobs_payload is _DEFAULT_PAYLOAD else jobs_payload
            return httpx.Response(
                200,
                json=payload,
            )

        return httpx.Response(
            trace_status,
            content=trace,
            headers={
                "Content-Type": trace_content_type,
            },
        )

    return handler


def test_job_log_uses_three_exact_get_boundaries() -> None:
    token = _valid_token()
    paths: list[str] = []

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        paths.append(request.url.path)

        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "gitlab.com"
        assert request.headers["PRIVATE-TOKEN"] == token
        assert token not in str(request.url)

        if request.url.path.endswith("/pipelines/latest"):
            assert request.headers["Accept"] == "application/json"
            assert dict(request.url.params) == {
                "ref": "main",
            }
            return httpx.Response(
                200,
                json=_pipeline_payload(),
            )

        if request.url.path.endswith(f"/pipelines/{_PIPELINE_ID}/jobs"):
            assert request.headers["Accept"] == "application/json"
            assert dict(request.url.params) == {
                "include_retried": "false",
                "page": "1",
                "per_page": str(MAX_PIPELINE_JOBS),
            }
            return httpx.Response(
                200,
                json=[_job_payload()],
            )

        assert request.url.path.endswith("/jobs/222/trace")
        assert request.headers["Accept"] == "text/plain"
        assert len(request.url.params) == 0

        return httpx.Response(
            200,
            content=b"line one\nline two\n",
            headers={
                "Content-Type": "text/plain",
            },
        )

    summary = _latest_log(_client(handler))

    assert paths == [
        ("/api/v4/projects/123456/pipelines/latest"),
        (f"/api/v4/projects/123456/pipelines/{_PIPELINE_ID}/jobs"),
        ("/api/v4/projects/123456/jobs/222/trace"),
    ]
    assert summary == JobLogSummary(
        job=JobSummary(
            job_id=222,
            name="security_scan",
            status=PipelineStatus.SUCCESS,
            pipeline_id=_PIPELINE_ID,
        ),
        text="line one\nline two",
        truncated=False,
    )


def test_failed_job_precedes_newer_successful_job() -> None:
    requested_trace = ""

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal requested_trace

        if request.url.path.endswith("/pipelines/latest"):
            return httpx.Response(
                200,
                json=_pipeline_payload(),
            )

        if request.url.path.endswith("/jobs"):
            return httpx.Response(
                200,
                json=[
                    _job_payload(
                        id=300,
                        status="success",
                    ),
                    _job_payload(
                        id=200,
                        name="failed_test",
                        status="failed",
                    ),
                ],
            )

        requested_trace = request.url.path

        return httpx.Response(
            200,
            text="failed trace",
        )

    summary = _latest_log(_client(handler))

    assert requested_trace.endswith("/jobs/200/trace")
    assert summary.job.status is PipelineStatus.FAILED


def test_newest_job_is_used_when_none_failed() -> None:
    requested_trace = ""

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal requested_trace

        if request.url.path.endswith("/pipelines/latest"):
            return httpx.Response(
                200,
                json=_pipeline_payload(),
            )

        if request.url.path.endswith("/jobs"):
            return httpx.Response(
                200,
                json=[
                    _job_payload(id=200),
                    _job_payload(
                        id=300,
                        name="newest",
                        status="running",
                    ),
                ],
            )

        requested_trace = request.url.path

        return httpx.Response(
            200,
            text="newest trace",
        )

    summary = _latest_log(_client(handler))

    assert requested_trace.endswith("/jobs/300/trace")
    assert summary.job.job_id == 300


@pytest.mark.parametrize(
    "status",
    tuple(item.value for item in PipelineStatus),
)
def test_documented_job_statuses_are_accepted(
    status: str,
) -> None:
    handler = _standard_handler(
        jobs_payload=[_job_payload(status=status)],
    )

    summary = _latest_log(_client(handler))

    assert summary.job.status is PipelineStatus(status)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("id", True),
        ("id", 0),
        ("id", 2**63),
        ("name", ""),
        ("name", "unsafe\nname"),
        ("name", "a" * 101),
        ("status", "unexpected"),
        ("status", None),
        ("ref", "other"),
        ("pipeline", None),
    ),
)
def test_invalid_job_fields_are_rejected(
    field: str,
    invalid_value: object,
) -> None:
    handler = _standard_handler(
        jobs_payload=[_job_payload(**{field: invalid_value})],
    )

    with pytest.raises(
        GitLabClientError,
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    ("pipeline_field", "invalid_value"),
    (
        ("id", 111),
        ("project_id", 654321),
        ("ref", "other"),
        ("sha", "b" * 40),
    ),
)
def test_mismatched_job_pipeline_is_rejected(
    pipeline_field: str,
    invalid_value: object,
) -> None:
    nested_pipeline = _job_payload()["pipeline"]
    assert isinstance(
        nested_pipeline,
        dict,
    )
    nested_pipeline[pipeline_field] = invalid_value

    handler = _standard_handler(
        jobs_payload=[_job_payload(pipeline=nested_pipeline)],
    )

    with pytest.raises(
        GitLabClientError,
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    ("invalid_jobs", "expected_kind"),
    (
        (
            None,
            GitLabErrorKind.INVALID_RESPONSE,
        ),
        (
            {},
            GitLabErrorKind.INVALID_RESPONSE,
        ),
        (
            "invalid",
            GitLabErrorKind.INVALID_RESPONSE,
        ),
        (
            [],
            (GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING),
        ),
    ),
)
def test_invalid_job_collections_are_controlled(
    invalid_jobs: object,
    expected_kind: GitLabErrorKind,
) -> None:
    handler = _standard_handler(
        jobs_payload=invalid_jobs,
    )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is expected_kind


def test_job_count_above_limit_is_rejected() -> None:
    jobs = [_job_payload(id=index + 1) for index in range(MAX_PIPELINE_JOBS + 1)]
    handler = _standard_handler(
        jobs_payload=jobs,
    )

    with pytest.raises(
        GitLabClientError,
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_duplicate_job_identifiers_are_rejected() -> None:
    handler = _standard_handler(
        jobs_payload=[
            _job_payload(),
            _job_payload(name="duplicate"),
        ],
    )

    with pytest.raises(
        GitLabClientError,
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    "content_type",
    (
        "text/plain",
        "application/octet-stream",
    ),
)
def test_supported_trace_types_are_accepted(
    content_type: str,
) -> None:
    handler = _standard_handler(
        trace=b"trace",
        trace_content_type=content_type,
    )

    assert _latest_log(_client(handler)).text == "trace"


def test_non_text_trace_is_rejected() -> None:
    handler = _standard_handler(
        trace=b'{"unsafe":"trace"}',
        trace_content_type=("application/json"),
    )

    with pytest.raises(
        GitLabClientError,
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_trace_above_byte_limit_is_rejected() -> None:
    handler = _standard_handler(
        trace=(b"A" * (MAX_GITLAB_TRACE_BYTES + 1)),
    )

    with pytest.raises(
        GitLabClientError,
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_trace_is_redacted_and_ansi_is_removed() -> None:
    real_token = _valid_token()
    telegram_token = "".join(
        (
            str(123_456_789),
            ":",
            "T" * 32,
        )
    )
    bearer = "bearer-sensitive-value"
    jwt = ".".join(
        (
            "eyJheader",
            "payload",
            "signature",
        )
    )
    trace = (
        "\x1b[31mfailed\x1b[0m\n"
        f"GITLAB_API_TOKEN={real_token}\n"
        f"TELEGRAM_BOT_TOKEN={telegram_token}\n"
        "PASSWORD=hunter2\n"
        f"Authorization: Bearer {bearer}\n"
        f"jwt={jwt}\n"
        "https://user:password@example.com/path\n"
    )

    handler = _standard_handler(
        trace=trace.encode(),
    )
    text = _latest_log(_client(handler)).text

    assert "\x1b" not in text
    assert real_token not in text
    assert telegram_token not in text
    assert "hunter2" not in text
    assert bearer not in text
    assert jwt not in text
    assert "user:password" not in text
    assert text.count("[REDACTED]") >= 6


def test_trace_keeps_only_last_bounded_lines() -> None:
    trace = "\n".join(f"line-{index}" for index in range(MAX_LOG_LINES + 5))
    handler = _standard_handler(
        trace=trace.encode(),
    )

    summary = _latest_log(_client(handler))

    assert summary.truncated is True
    assert "line-0" not in summary.text
    assert f"line-{MAX_LOG_LINES + 4}" in summary.text
    assert len(summary.text.splitlines()) == MAX_LOG_LINES


def test_trace_character_count_is_bounded() -> None:
    trace = b"X" * (MAX_LOG_OUTPUT_CHARACTERS + 100)
    handler = _standard_handler(
        trace=trace,
    )

    summary = _latest_log(_client(handler))

    assert summary.truncated is True
    assert len(summary.text) <= MAX_LOG_OUTPUT_CHARACTERS


def test_empty_trace_returns_placeholder() -> None:
    handler = _standard_handler(
        trace=b"\x00\r\n",
    )

    summary = _latest_log(_client(handler))

    assert summary.text == "(no log output)"
    assert summary.truncated is False


@pytest.mark.parametrize(
    ("status_code", "expected_kind"),
    (
        (
            401,
            GitLabErrorKind.AUTHENTICATION,
        ),
        (
            403,
            (GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING),
        ),
        (
            404,
            (GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING),
        ),
        (
            429,
            GitLabErrorKind.RATE_LIMITED,
        ),
        (
            500,
            GitLabErrorKind.UPSTREAM,
        ),
        (
            418,
            GitLabErrorKind.INVALID_RESPONSE,
        ),
    ),
)
def test_trace_http_failures_are_controlled(
    status_code: int,
    expected_kind: GitLabErrorKind,
) -> None:
    sensitive_body = _valid_token() + " DO-NOT-LEAK"
    handler = _standard_handler(
        trace=sensitive_body.encode(),
        trace_status=status_code,
    )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is expected_kind
    assert sensitive_body not in str(error.value)


def test_trace_redirect_is_not_followed() -> None:
    request_count = 0

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        if request.url.path.endswith("/pipelines/latest"):
            return httpx.Response(
                200,
                json=_pipeline_payload(),
            )

        if request.url.path.endswith("/jobs"):
            return httpx.Response(
                200,
                json=[_job_payload()],
            )

        return httpx.Response(
            302,
            headers={
                "Location": ("https://example.invalid/steal"),
            },
        )

    with pytest.raises(
        GitLabClientError,
    ) as error:
        _latest_log(_client(handler))

    assert request_count == 3
    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_trace_timeout_is_static_network_failure() -> None:
    sensitive_detail = "DO-NOT-LEAK-TIMEOUT"

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith("/pipelines/latest"):
            return httpx.Response(
                200,
                json=_pipeline_payload(),
            )

        if request.url.path.endswith("/jobs"):
            return httpx.Response(
                200,
                json=[_job_payload()],
            )

        raise httpx.ReadTimeout(
            sensitive_detail,
            request=request,
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.NETWORK
    assert sensitive_detail not in str(error.value)
    assert _valid_token() not in str(error.value)


def _latest_failed_log(
    client: GitLabJobLogClient,
) -> JobLogSummary:
    return asyncio.run(client.get_latest_failed_job_log())


def test_latest_failed_log_uses_exact_filtered_boundary() -> None:
    token = _valid_token()
    paths: list[str] = []

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        paths.append(request.url.path)

        assert request.method == "GET"
        assert request.headers["PRIVATE-TOKEN"] == token
        assert token not in str(request.url)

        if request.url.path == ("/api/v4/projects/123456/pipelines"):
            assert request.headers["Accept"] == "application/json"
            assert dict(request.url.params) == {
                "ref": "main",
                "status": "failed",
                "order_by": "id",
                "sort": "desc",
                "page": "1",
                "per_page": "1",
            }
            pipeline = _pipeline_payload()
            pipeline["status"] = "failed"

            return httpx.Response(
                200,
                json=[pipeline],
            )

        if request.url.path.endswith(f"/pipelines/{_PIPELINE_ID}/jobs"):
            return httpx.Response(
                200,
                json=[
                    _job_payload(
                        name="unit_tests",
                        status="failed",
                    )
                ],
            )

        assert request.url.path.endswith("/jobs/222/trace")

        return httpx.Response(
            200,
            content=b"one failed test\n",
            headers={
                "Content-Type": "text/plain",
            },
        )

    summary = _latest_failed_log(_client(handler))

    assert paths == [
        "/api/v4/projects/123456/pipelines",
        (f"/api/v4/projects/123456/pipelines/{_PIPELINE_ID}/jobs"),
        "/api/v4/projects/123456/jobs/222/trace",
    ]
    assert summary == JobLogSummary(
        job=JobSummary(
            job_id=222,
            name="unit_tests",
            status=PipelineStatus.FAILED,
            pipeline_id=_PIPELINE_ID,
        ),
        text="one failed test",
        truncated=False,
    )


def test_latest_failed_log_rejects_missing_pipeline() -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        assert request.url.path.endswith("/pipelines")

        return httpx.Response(
            200,
            json=[],
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_failed_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING


def test_latest_failed_log_rejects_non_failed_pipeline() -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        assert request.url.path.endswith("/pipelines")

        return httpx.Response(
            200,
            json=[_pipeline_payload()],
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_failed_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_latest_failed_log_requires_a_failed_job() -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith("/pipelines"):
            pipeline = _pipeline_payload()
            pipeline["status"] = "failed"

            return httpx.Response(
                200,
                json=[pipeline],
            )

        if request.url.path.endswith("/jobs"):
            return httpx.Response(
                200,
                json=[
                    _job_payload(
                        name="unit_tests",
                        status="success",
                    )
                ],
            )

        pytest.fail("A successful job trace must not be requested.")

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_failed_log(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE

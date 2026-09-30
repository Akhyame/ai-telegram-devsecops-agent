"""Offline tests for the bounded read-only GitLab client."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from bot.gitlab_client import (
    MAX_GITLAB_RESPONSE_BYTES,
    GitLabClient,
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_config import GitLabSettings

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = 123456
_DEFAULT_REF = "main"
_VALID_SHA = "a" * 40


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


def _payload(
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": 987654,
        "project_id": _PROJECT_ID,
        "status": "success",
        "ref": _DEFAULT_REF,
        "sha": _VALID_SHA,
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
) -> GitLabClient:
    return GitLabClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )


def _latest_pipeline(
    client: GitLabClient,
) -> PipelineSummary:
    return asyncio.run(client.get_latest_pipeline())


def test_latest_pipeline_uses_exact_read_only_request_boundary() -> None:
    token = _valid_token()
    request_count = 0

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "gitlab.com"
        assert request.url.path == ("/api/v4/projects/123456/pipelines/latest")
        assert request.url.params.get("ref") == "main"
        assert len(request.url.params) == 1
        assert request.headers["PRIVATE-TOKEN"] == token
        assert request.headers["Accept"] == ("application/json")
        assert token not in str(request.url)

        return httpx.Response(
            200,
            json=_payload(),
        )

    summary = _latest_pipeline(_client(handler))

    assert request_count == 1
    assert summary == PipelineSummary(
        pipeline_id=987654,
        status=PipelineStatus.SUCCESS,
        ref="main",
        sha=_VALID_SHA,
    )


@pytest.mark.parametrize(
    "status",
    tuple(item.value for item in PipelineStatus),
)
def test_all_documented_pipeline_statuses_are_accepted(
    status: str,
) -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=_payload(status=status),
        )

    summary = _latest_pipeline(_client(handler))

    assert summary.status is PipelineStatus(status)


@pytest.mark.parametrize(
    ("status_code", "expected_kind"),
    (
        (401, GitLabErrorKind.AUTHENTICATION),
        (
            403,
            GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING,
        ),
        (404, GitLabErrorKind.PROJECT_NOT_FOUND),
        (429, GitLabErrorKind.RATE_LIMITED),
        (500, GitLabErrorKind.UPSTREAM),
        (502, GitLabErrorKind.UPSTREAM),
        (418, GitLabErrorKind.INVALID_RESPONSE),
    ),
)
def test_http_failures_map_to_controlled_categories(
    status_code: int,
    expected_kind: GitLabErrorKind,
) -> None:
    sensitive_body = _valid_token() + " DO-NOT-LEAK-RESPONSE-BODY"

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code,
            text=sensitive_body,
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is expected_kind
    assert sensitive_body not in str(error.value)
    assert _valid_token() not in str(error.value)


def test_redirect_is_rejected_without_following_location() -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            302,
            headers={
                "Location": ("https://example.invalid/steal"),
            },
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_pipeline(_client(handler))

    assert request_count == 1
    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_non_json_content_type_is_rejected() -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            text="DO-NOT-PARSE",
            headers={
                "Content-Type": "text/plain",
            },
        )

    with pytest.raises(GitLabClientError) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_malformed_json_is_rejected() -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{not-json",
            headers={
                "Content-Type": "application/json",
            },
        )

    with pytest.raises(GitLabClientError) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    "invalid_root",
    (
        None,
        [],
        "invalid",
        123,
    ),
)
def test_non_object_json_root_is_rejected(
    invalid_root: object,
) -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=invalid_root,
        )

    with pytest.raises(GitLabClientError) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("id", True),
        ("id", 0),
        ("id", (2**63)),
        ("project_id", True),
        ("project_id", 654321),
        ("status", "unexpected"),
        ("status", None),
        ("ref", "other"),
        ("ref", None),
        ("sha", "A" * 40),
        ("sha", "a" * 39),
        ("sha", None),
    ),
)
def test_invalid_pipeline_fields_are_rejected(
    field: str,
    invalid_value: object,
) -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=_payload(
                **{field: invalid_value},
            ),
        )

    with pytest.raises(GitLabClientError) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_sha256_commit_identifier_is_accepted() -> None:
    sha256 = "b" * 64

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=_payload(sha=sha256),
        )

    summary = _latest_pipeline(_client(handler))

    assert summary.sha == sha256


def test_response_larger_than_limit_is_rejected() -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"A" * (MAX_GITLAB_RESPONSE_BYTES + 1),
            headers={
                "Content-Type": "application/json",
            },
        )

    with pytest.raises(GitLabClientError) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_invalid_content_length_is_rejected() -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": "not-a-number",
            },
        )

    with pytest.raises(GitLabClientError) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_timeout_maps_to_static_network_failure() -> None:
    sensitive_detail = "DO-NOT-LEAK-TIMEOUT-DETAIL"

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        raise httpx.ReadTimeout(
            sensitive_detail,
            request=request,
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _latest_pipeline(_client(handler))

    assert error.value.kind is GitLabErrorKind.NETWORK
    assert sensitive_detail not in str(error.value)
    assert _valid_token() not in str(error.value)

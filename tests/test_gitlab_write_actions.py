"""Offline tests for controlled GitLab cancel and retry actions."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from bot.gitlab_client import (
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_write_client import GitLabWriteClient
from bot.gitlab_write_config import GitLabWriteSettings

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = 123456
_ALLOWED_REF = "main"
_PIPELINE_ID = 987654
_VALID_SHA = "a" * 40


def _valid_write_token() -> str:
    return "".join(
        (
            "gl",
            "pat-",
            "W" * 24,
            ".",
            "w" * 24,
        )
    )


def _settings() -> GitLabWriteSettings:
    return GitLabWriteSettings(
        GITLAB_API_URL=_API_URL,
        GITLAB_PROJECT_ID=str(_PROJECT_ID),
        GITLAB_DEFAULT_REF=_ALLOWED_REF,
        GITLAB_WRITE_API_TOKEN=_valid_write_token(),
    )


def _payload(
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": _PIPELINE_ID,
        "project_id": _PROJECT_ID,
        "status": "running",
        "ref": _ALLOWED_REF,
        "sha": _VALID_SHA,
        "variables": [
            {
                "key": "UNTRUSTED",
                "value": "DO-NOT-RETURN",
            },
        ],
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
) -> GitLabWriteClient:
    return GitLabWriteClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )


def _run_action(
    client: GitLabWriteClient,
    action: str,
    pipeline_id: object = _PIPELINE_ID,
) -> PipelineSummary:
    method = getattr(client, action)
    return asyncio.run(method(pipeline_id))


@pytest.mark.parametrize(
    (
        "action",
        "preflight_status",
        "result_status",
        "suffix",
    ),
    (
        (
            "cancel_pipeline",
            "running",
            "canceled",
            "cancel",
        ),
        (
            "retry_pipeline",
            "failed",
            "pending",
            "retry",
        ),
        (
            "retry_pipeline",
            "canceled",
            "pending",
            "retry",
        ),
    ),
)
def test_actions_use_preflight_then_exact_controlled_mutation(
    action: str,
    preflight_status: str,
    result_status: str,
    suffix: str,
) -> None:
    token = _valid_write_token()
    requests: list[httpx.Request] = []

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        requests.append(request)

        if len(requests) == 1:
            return httpx.Response(
                200,
                json=_payload(status=preflight_status),
            )

        return httpx.Response(
            200,
            json=_payload(status=result_status),
        )

    summary = _run_action(
        _client(handler),
        action,
    )

    assert len(requests) == 2

    preflight, mutation = requests
    expected_base_path = "/api/v4/projects/123456/pipelines/987654"

    assert preflight.method == "GET"
    assert preflight.url.path == expected_base_path
    assert len(preflight.url.params) == 0
    assert preflight.read() == b""

    assert mutation.method == "POST"
    assert mutation.url.path == f"{expected_base_path}/{suffix}"
    assert len(mutation.url.params) == 0
    assert mutation.read() == b""
    assert "Content-Type" not in mutation.headers

    for request in requests:
        assert request.url.scheme == "https"
        assert request.url.host == "gitlab.com"
        assert request.headers["PRIVATE-TOKEN"] == token
        assert request.headers["Accept"] == "application/json"
        assert token not in str(request.url)

    assert summary == PipelineSummary(
        pipeline_id=_PIPELINE_ID,
        status=PipelineStatus(result_status),
        ref=_ALLOWED_REF,
        sha=_VALID_SHA,
    )


@pytest.mark.parametrize(
    "status",
    (
        PipelineStatus.CREATED,
        PipelineStatus.WAITING_FOR_RESOURCE,
        PipelineStatus.PREPARING,
        PipelineStatus.WAITING_FOR_CALLBACK,
        PipelineStatus.PENDING,
        PipelineStatus.RUNNING,
        PipelineStatus.MANUAL,
        PipelineStatus.SCHEDULED,
    ),
)
def test_cancel_allows_only_active_allowlisted_states(
    status: PipelineStatus,
) -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            return httpx.Response(
                200,
                json=_payload(status=status.value),
            )

        return httpx.Response(
            200,
            json=_payload(status="canceled"),
        )

    summary = _run_action(
        _client(handler),
        "cancel_pipeline",
    )

    assert request_count == 2
    assert summary.status is PipelineStatus.CANCELED


@pytest.mark.parametrize(
    "status",
    (
        PipelineStatus.SUCCESS,
        PipelineStatus.FAILED,
        PipelineStatus.CANCELING,
        PipelineStatus.CANCELED,
        PipelineStatus.SKIPPED,
    ),
)
def test_cancel_denies_non_active_states_before_mutation(
    status: PipelineStatus,
) -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            200,
            json=_payload(status=status.value),
        )

    with pytest.raises(GitLabClientError) as error:
        _run_action(
            _client(handler),
            "cancel_pipeline",
        )

    assert request_count == 1
    assert error.value.kind is GitLabErrorKind.ACTION_NOT_ALLOWED


@pytest.mark.parametrize(
    "status",
    tuple(
        status
        for status in PipelineStatus
        if status
        not in {
            PipelineStatus.FAILED,
            PipelineStatus.CANCELED,
        }
    ),
)
def test_retry_denies_non_retryable_states_before_mutation(
    status: PipelineStatus,
) -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            200,
            json=_payload(status=status.value),
        )

    with pytest.raises(GitLabClientError) as error:
        _run_action(
            _client(handler),
            "retry_pipeline",
        )

    assert request_count == 1
    assert error.value.kind is GitLabErrorKind.ACTION_NOT_ALLOWED


@pytest.mark.parametrize(
    "action",
    (
        "cancel_pipeline",
        "retry_pipeline",
    ),
)
@pytest.mark.parametrize(
    "invalid_pipeline_id",
    (
        None,
        True,
        False,
        "987654",
        0,
        -1,
        2**63,
    ),
)
def test_invalid_pipeline_id_is_denied_without_network_request(
    action: str,
    invalid_pipeline_id: object,
) -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return httpx.Response(500)

    with pytest.raises(GitLabClientError) as error:
        _run_action(
            _client(handler),
            action,
            invalid_pipeline_id,
        )

    assert request_count == 0
    assert error.value.kind is GitLabErrorKind.ACTION_NOT_ALLOWED


@pytest.mark.parametrize(
    (
        "field",
        "invalid_value",
    ),
    (
        ("id", _PIPELINE_ID + 1),
        ("project_id", _PROJECT_ID + 1),
        ("ref", "other"),
        ("status", "unknown"),
        ("sha", "A" * 40),
    ),
)
def test_invalid_preflight_target_is_rejected_before_mutation(
    field: str,
    invalid_value: object,
) -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            200,
            json=_payload(
                **{field: invalid_value},
            ),
        )

    with pytest.raises(GitLabClientError) as error:
        _run_action(
            _client(handler),
            "cancel_pipeline",
        )

    assert request_count == 1
    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    "action",
    (
        "cancel_pipeline",
        "retry_pipeline",
    ),
)
def test_pipeline_scoped_not_found_is_generic(
    action: str,
) -> None:
    sensitive_body = "DO-NOT-LEAK-MISSING-TARGET"

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            404,
            text=sensitive_body,
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run_action(
            _client(handler),
            action,
        )

    assert error.value.kind is GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING
    assert sensitive_body not in str(error.value)


def test_mutation_response_must_match_confirmed_pipeline() -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            return httpx.Response(
                200,
                json=_payload(status="failed"),
            )

        return httpx.Response(
            200,
            json=_payload(
                id=_PIPELINE_ID + 1,
                status="pending",
            ),
        )

    with pytest.raises(GitLabClientError) as error:
        _run_action(
            _client(handler),
            "retry_pipeline",
        )

    assert request_count == 2
    assert error.value.kind is GitLabErrorKind.INVALID_RESPONSE


def test_mutation_failure_is_static_and_redacted() -> None:
    sensitive_body = _valid_write_token() + " DO-NOT-LEAK-MUTATION-RESPONSE"
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        if request_count == 1:
            return httpx.Response(
                200,
                json=_payload(status="running"),
            )

        return httpx.Response(
            500,
            text=sensitive_body,
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run_action(
            _client(handler),
            "cancel_pipeline",
        )

    assert request_count == 2
    assert error.value.kind is GitLabErrorKind.UPSTREAM
    assert sensitive_body not in str(error.value)
    assert _valid_write_token() not in str(error.value)

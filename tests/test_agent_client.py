"""Offline tests for the bounded local Ollama client."""

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from agent.client import (
    MAX_AI_RESPONSE_BYTES,
    AIClientError,
    AIErrorKind,
    LocalAIClient,
)
from agent.config import AISettings
from agent.models import (
    Confidence,
    FailureCode,
    FailureExplanation,
    NormalizedFailure,
    PipelineJob,
)

_API_URL = "http://127.0.0.1:11434/api"
_MODEL = "qwen3.5:4b"


def _settings(
    **overrides: Any,
) -> AISettings:
    values: dict[str, Any] = {
        "AI_PROVIDER": "ollama-local",
        "OLLAMA_API_URL": _API_URL,
        "OLLAMA_MODEL": _MODEL,
        "AI_REQUEST_TIMEOUT_SECONDS": "60",
        "AI_MAX_OUTPUT_CHARS": "1200",
    }
    values.update(overrides)

    return AISettings(**values)


def _failure() -> NormalizedFailure:
    return NormalizedFailure(
        job=PipelineJob.UNIT_TESTS,
        failure_code=FailureCode.DEPENDENCY_DOWNLOAD_TIMEOUT,
    )


def _explanation_payload(
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "summary": "The dependency installation timed out.",
        "likely_cause": "The package download exceeded the configured timeout.",
        "safe_next_step": "Review the dependency cache and retry once.",
        "confidence": "high",
    }
    payload.update(overrides)

    return payload


def _ollama_payload(
    *,
    content: str | None = None,
    **overrides: Any,
) -> dict[str, Any]:
    if content is None:
        content = json.dumps(
            _explanation_payload(),
            separators=(",", ":"),
        )

    payload: dict[str, Any] = {
        "model": _MODEL,
        "created_at": "2026-08-29T00:00:00Z",
        "message": {
            "role": "assistant",
            "content": content,
            "thinking": "",
        },
        "done": True,
        "done_reason": "stop",
        "total_duration": 1,
        "eval_count": 10,
    }
    payload.update(overrides)

    return payload


def _client(
    handler: Callable[
        [httpx.Request],
        httpx.Response,
    ],
    **settings_overrides: Any,
) -> LocalAIClient:
    return LocalAIClient(
        _settings(**settings_overrides),
        transport=httpx.MockTransport(handler),
    )


def _run(
    client: LocalAIClient,
    failure: object | None = None,
) -> FailureExplanation:
    if failure is None:
        failure = _failure()

    return asyncio.run(client.explain_failure(failure))


def test_request_uses_exact_local_read_only_boundary() -> None:
    request_count = 0

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        assert request.method == "POST"
        assert request.url.scheme == "http"
        assert request.url.host == "127.0.0.1"
        assert request.url.port == 11434
        assert request.url.path == "/api/chat"
        assert len(request.url.params) == 0

        assert request.headers["Accept"] == "application/json"
        assert request.headers["Content-Type"] == "application/json"
        assert "Authorization" not in request.headers
        assert "PRIVATE-TOKEN" not in request.headers
        assert "X-API-Key" not in request.headers

        request_body = json.loads(request.read())

        assert set(request_body) == {
            "model",
            "stream",
            "think",
            "keep_alive",
            "format",
            "options",
            "messages",
        }
        assert request_body["model"] == _MODEL
        assert request_body["stream"] is False
        assert request_body["think"] is False
        assert request_body["keep_alive"] == "5m"
        assert request_body["options"] == {
            "temperature": 0,
            "num_predict": 350,
        }
        assert "tools" not in request_body

        assert request_body["format"] == (FailureExplanation.model_json_schema())

        messages = request_body["messages"]

        assert [message["role"] for message in messages] == [
            "system",
            "user",
        ]

        user_payload = json.loads(
            messages[1]["content"],
        )

        assert user_payload == {
            "task": "explain_pipeline_failure",
            "failure": {
                "job": "unit_tests",
                "failure_code": "dependency_download_timeout",
            },
        }
        assert "raw_log" not in user_payload["failure"]
        assert "blocking_findings" not in user_payload["failure"]
        assert "total_findings" not in user_payload["failure"]

        return httpx.Response(
            200,
            json=_ollama_payload(),
        )

    explanation = _run(
        _client(handler),
    )

    assert request_count == 1
    assert explanation == FailureExplanation(
        summary="The dependency installation timed out.",
        likely_cause="The package download exceeded the configured timeout.",
        safe_next_step="Review the dependency cache and retry once.",
        confidence=Confidence.HIGH,
    )


def test_non_normalized_input_is_rejected_without_request() -> None:
    request_count = 0

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            200,
            json=_ollama_payload(),
        )

    with pytest.raises(
        TypeError,
        match=r"\AA normalized failure is required\.\Z",
    ):
        _run(
            _client(handler),
            {
                "raw_log": "DO-NOT-SEND",
            },
        )

    assert request_count == 0


@pytest.mark.parametrize(
    "status_code",
    (
        302,
        400,
        404,
        429,
        500,
        503,
    ),
)
def test_http_failures_are_generic_and_unavailable(
    status_code: int,
) -> None:
    response_marker = "DO-NOT-LEAK-RESPONSE"

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code,
            text=response_marker,
        )

    with pytest.raises(
        AIClientError,
        match=r"\ALocal AI request failed\.\Z",
    ) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.UNAVAILABLE
    assert response_marker not in str(error.value)


def test_timeout_is_mapped_without_leaking_details() -> None:
    timeout_marker = "DO-NOT-LEAK-TIMEOUT"

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        raise httpx.ReadTimeout(
            timeout_marker,
            request=request,
        )

    with pytest.raises(
        AIClientError,
        match=r"\ALocal AI request failed\.\Z",
    ) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.TIMEOUT
    assert timeout_marker not in str(error.value)


def test_network_failure_is_mapped_without_leaking_details() -> None:
    network_marker = "DO-NOT-LEAK-NETWORK"

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        raise httpx.ConnectError(
            network_marker,
            request=request,
        )

    with pytest.raises(
        AIClientError,
        match=r"\ALocal AI request failed\.\Z",
    ) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.NETWORK
    assert network_marker not in str(error.value)


def test_non_json_content_type_is_rejected() -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "text/plain",
            },
            text="DO-NOT-PARSE",
        )

    with pytest.raises(AIClientError) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE


def test_declared_oversized_response_is_rejected() -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "application/json",
                "content-length": str(MAX_AI_RESPONSE_BYTES + 1),
            },
            content=b"{}",
        )

    with pytest.raises(AIClientError) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    (
        "outer_overrides",
        "message_overrides",
    ),
    (
        (
            {
                "model": "unexpected-model",
            },
            {},
        ),
        (
            {
                "done": False,
            },
            {},
        ),
        (
            {
                "done_reason": "length",
            },
            {},
        ),
        (
            {},
            {
                "role": "user",
            },
        ),
        (
            {},
            {
                "thinking": "DO-NOT-RETURN-THINKING",
            },
        ),
        (
            {},
            {
                "content": "",
            },
        ),
        (
            {},
            {
                "tool_calls": [
                    {
                        "function": {
                            "name": "run_command",
                        },
                    },
                ],
            },
        ),
    ),
)
def test_untrusted_response_envelope_is_rejected(
    outer_overrides: dict[str, Any],
    message_overrides: dict[str, Any],
) -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        payload = _ollama_payload()
        payload.update(outer_overrides)
        payload["message"].update(message_overrides)

        return httpx.Response(
            200,
            json=payload,
        )

    with pytest.raises(
        AIClientError,
        match=r"\ALocal AI request failed\.\Z",
    ) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE


@pytest.mark.parametrize(
    "invalid_output",
    (
        {
            "summary": "",
        },
        {
            "summary": "A" * 301,
        },
        {
            "summary": "first line\nsecond line",
        },
        {
            "confidence": "certain",
        },
        {
            "unexpected": "run remediation",
        },
    ),
)
def test_invalid_structured_output_is_rejected(
    invalid_output: dict[str, Any],
) -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        output = _explanation_payload(**invalid_output)

        return httpx.Response(
            200,
            json=_ollama_payload(
                content=json.dumps(output),
            ),
        )

    with pytest.raises(AIClientError) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE


def test_duplicate_output_keys_are_rejected() -> None:
    duplicate_content = "".join(
        (
            '{"summary":"first",',
            '"summary":"second",',
            '"likely_cause":"cause",',
            '"safe_next_step":"step",',
            '"confidence":"low"}',
        )
    )

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=_ollama_payload(
                content=duplicate_content,
            ),
        )

    with pytest.raises(AIClientError) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE


def test_configured_output_character_limit_is_enforced() -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=_ollama_payload(),
        )

    with pytest.raises(AIClientError) as error:
        _run(
            _client(
                handler,
                AI_MAX_OUTPUT_CHARS="200",
            ),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE

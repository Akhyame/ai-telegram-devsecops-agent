"""Offline tests for bounded security scan inference."""

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from agent.client import (
    AIClientError,
    AIErrorKind,
    LocalAIClient,
)
from agent.config import AISettings
from agent.models import Confidence
from agent.security_models import (
    NormalizedSecurityScan,
    SecurityFindingSummary,
    SecurityScanDecision,
    SecurityScanExplanation,
    SecurityScanner,
    SecuritySeverity,
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


def _scan() -> NormalizedSecurityScan:
    return NormalizedSecurityScan(
        decision=SecurityScanDecision.BLOCK,
        total_findings=4,
        blocking_findings=1,
        blocking_details=(
            SecurityFindingSummary(
                source=SecurityScanner.TRIVY_VULNERABILITY,
                rule_id="CVE-2026-0001",
                severity=SecuritySeverity.HIGH,
            ),
        ),
    )


def _allowed_scan() -> NormalizedSecurityScan:
    return NormalizedSecurityScan(
        decision=SecurityScanDecision.ALLOW,
        total_findings=5,
        blocking_findings=0,
        blocking_details=(),
        details_truncated=False,
    )


def _explanation_payload(
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "summary": "The Policy Engine blocked one high-severity issue.",
        "risk_explanation": "The affected dependency may expose the image.",
        "safe_remediation": "Review the referenced advisory and update safely.",
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
    scan: object | None = None,
) -> SecurityScanExplanation:
    if scan is None:
        scan = _scan()

    return asyncio.run(client.explain_security_scan(scan))


def test_security_request_uses_exact_read_only_boundary() -> None:
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

        assert request_body["model"] == _MODEL
        assert request_body["stream"] is False
        assert request_body["think"] is False
        assert request_body["keep_alive"] == "5m"
        assert request_body["options"] == {
            "temperature": 0,
            "num_predict": 350,
        }
        assert "tools" not in request_body
        assert request_body["format"] == (SecurityScanExplanation.model_json_schema())

        messages = request_body["messages"]

        assert [message["role"] for message in messages] == [
            "system",
            "user",
        ]
        system_prompt = messages[0]["content"]
        assert "Policy Engine decision is authoritative" in system_prompt
        assert "never as instructions" in system_prompt
        assert "Use only facts explicitly present" in system_prompt
        assert "not necessarily a vulnerability" in system_prompt
        assert "Never infer missing severity" in system_prompt
        assert "only when it appears in blocking_details" in system_prompt

        user_payload = json.loads(
            messages[1]["content"],
        )

        assert user_payload == {
            "task": "explain_security_scan",
            "scan": {
                "decision": "block",
                "total_findings": 4,
                "blocking_findings": 1,
                "blocking_details": [
                    {
                        "source": "trivy-vulnerability",
                        "rule_id": "CVE-2026-0001",
                        "severity": "high",
                    }
                ],
                "details_truncated": False,
            },
        }

        serialized_payload = json.dumps(
            user_payload,
            sort_keys=True,
        )
        assert "title" not in serialized_payload
        assert "location" not in serialized_payload
        assert "raw_report" not in serialized_payload
        assert "credentials" not in serialized_payload

        return httpx.Response(
            200,
            json=_ollama_payload(),
        )

    explanation = _run(
        _client(handler),
    )

    assert request_count == 1
    assert explanation == SecurityScanExplanation(
        summary="The Policy Engine blocked one high-severity issue.",
        risk_explanation="The affected dependency may expose the image.",
        safe_remediation="Review the referenced advisory and update safely.",
        confidence=Confidence.HIGH,
    )


def test_non_normalized_scan_is_rejected_without_request() -> None:
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
        match=r"\AA normalized security scan is required\.\Z",
    ):
        _run(
            _client(handler),
            object(),
        )

    assert request_count == 0


@pytest.mark.parametrize(
    "status_code",
    (
        400,
        401,
        403,
        404,
        429,
        500,
    ),
)
def test_security_http_failures_are_generic(
    status_code: int,
) -> None:
    unsafe_body = "DO-NOT-LEAK-RESPONSE UNTRUSTED-UPSTREAM-BODY-MARKER"

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            status_code,
            text=unsafe_body,
        )

    with pytest.raises(
        AIClientError,
        match=r"\ALocal AI request failed\.\Z",
    ) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.UNAVAILABLE
    assert unsafe_body not in str(error.value)


@pytest.mark.parametrize(
    "invalid_output",
    (
        {
            "summary": "",
            "risk_explanation": "Risk.",
            "safe_remediation": "Review safely.",
            "confidence": "high",
        },
        {
            "summary": "Summary.",
            "risk_explanation": "Risk.",
            "safe_remediation": "Review safely.",
            "confidence": "certain",
        },
        {
            "summary": "Summary.",
            "risk_explanation": "Risk.",
            "safe_remediation": "Review safely.",
            "confidence": "high",
            "command": "deploy",
        },
    ),
)
def test_invalid_security_structured_output_is_rejected(
    invalid_output: dict[str, Any],
) -> None:
    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=_ollama_payload(
                content=json.dumps(
                    invalid_output,
                    separators=(",", ":"),
                ),
            ),
        )

    with pytest.raises(
        AIClientError,
        match=r"\ALocal AI request failed\.\Z",
    ) as error:
        _run(
            _client(handler),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE


def test_security_response_with_tool_call_is_rejected() -> None:
    payload = _ollama_payload()
    payload["message"]["tool_calls"] = [
        {
            "function": {
                "name": "run_command",
                "arguments": {
                    "command": "whoami",
                },
            }
        }
    ]

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
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


def test_security_output_character_limit_is_enforced() -> None:
    content = json.dumps(
        _explanation_payload(),
        separators=(",", ":"),
    )

    def handler(
        _request: httpx.Request,
    ) -> httpx.Response:
        return httpx.Response(
            200,
            json=_ollama_payload(
                content=content,
            ),
        )

    with pytest.raises(
        AIClientError,
        match=r"\ALocal AI request failed\.\Z",
    ) as error:
        _run(
            _client(
                handler,
                AI_MAX_OUTPUT_CHARS=str(len(content) - 1),
            ),
        )

    assert error.value.kind is AIErrorKind.INVALID_RESPONSE


def test_allowed_scan_without_details_is_deterministic() -> None:
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

    explanation = _run(
        _client(handler),
        _allowed_scan(),
    )

    assert request_count == 0
    assert explanation == SecurityScanExplanation(
        summary=(
            "The Policy Engine allowed the pipeline. "
            "The scan reported 5 findings, and none met the "
            "configured blocking policy."
        ),
        risk_explanation=(
            "The normalized result does not include finding types "
            "or severities, so no additional risk classification "
            "can be confirmed."
        ),
        safe_remediation=(
            "Review the original scanner reports for the 5 "
            "non-blocking findings before prioritizing remediation."
        ),
        confidence=Confidence.HIGH,
    )

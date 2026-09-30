"""Offline tests for deterministic Security Gate block evidence."""

import asyncio

import httpx
import pytest

from bot.gitlab_config import GitLabSettings
from sample_app.security_gate_evidence import (
    MAX_SECURITY_GATE_RESPONSE_BYTES,
    GitLabSecurityGateEvidenceClient,
    SecurityGateBlockEvidence,
    SecurityGateEvidenceError,
)
from sample_app.webhook_events import (
    PipelineEventStatus,
    PipelineWebhookEvent,
)

_PROJECT_ID = 85705009
_PIPELINE_ID = 987654
_JOB_ID = 123456
_SHA = "a" * 40
_TOKEN = "glpat-" + ("A" * 32)


def _settings() -> GitLabSettings:
    return GitLabSettings(
        GITLAB_API_URL="https://gitlab.com/api/v4",
        GITLAB_PROJECT_ID=_PROJECT_ID,
        GITLAB_DEFAULT_REF="main",
        GITLAB_API_TOKEN=_TOKEN,
    )


def _event(
    status: PipelineEventStatus = PipelineEventStatus.FAILED,
) -> PipelineWebhookEvent:
    return PipelineWebhookEvent(
        pipeline_id=_PIPELINE_ID,
        status=status,
        ref="main",
        sha=_SHA,
    )


def _job(
    *,
    status: str = "failed",
    sha: str = _SHA,
) -> dict[str, object]:
    return {
        "id": _JOB_ID,
        "name": "security_gate",
        "stage": "security_gate",
        "status": status,
        "ref": "main",
        "pipeline": {
            "id": _PIPELINE_ID,
            "project_id": _PROJECT_ID,
            "ref": "main",
            "sha": sha,
        },
    }


def _json_response(payload: object) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        json=payload,
    )


def test_block_marker_returns_minimal_validated_evidence() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)

        if request.url.path.endswith("/jobs"):
            return _json_response([_job()])

        return httpx.Response(
            200,
            headers={"Content-Type": "text/plain"},
            content=(b"controlled output\nSecurity gate decision: BLOCK (2/7 blocking findings)\n"),
        )

    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    evidence = asyncio.run(client.get_block_evidence(_event()))

    assert evidence == SecurityGateBlockEvidence(
        blocking_findings=2,
        total_findings=7,
    )
    assert len(requests) == 2
    assert all(request.headers["private-token"] == _TOKEN for request in requests)
    assert requests[0].url.params["include_retried"] == "false"
    assert requests[0].url.params["per_page"] == "100"


@pytest.mark.parametrize(
    "trace",
    (
        b"Security gate decision: ALLOW (0/3 blocking findings)\n",
        b"Security gate error: Scanner report is invalid\n",
        b"unrelated technical failure\n",
    ),
)
def test_non_block_trace_returns_no_vulnerability_evidence(
    trace: bytes,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jobs"):
            return _json_response([_job()])

        return httpx.Response(200, content=trace)

    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(client.get_block_evidence(_event())) is None


@pytest.mark.parametrize(
    "job_status",
    (
        "created",
        "running",
        "success",
        "skipped",
        "canceled",
    ),
)
def test_non_failed_gate_job_performs_no_trace_request(
    job_status: str,
) -> None:
    request_count = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        return _json_response([_job(status=job_status)])

    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(client.get_block_evidence(_event())) is None
    assert request_count == 1


def test_non_failed_pipeline_performs_no_request() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("Non-failed pipeline attempted GitLab access.")

    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    assert (
        asyncio.run(
            client.get_block_evidence(
                _event(PipelineEventStatus.SUCCESS),
            )
        )
        is None
    )


def test_missing_gate_job_returns_no_evidence() -> None:
    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(
            lambda _request: _json_response(
                [
                    {
                        "id": 11,
                        "name": "unit_tests",
                    }
                ]
            )
        ),
    )

    assert asyncio.run(client.get_block_evidence(_event())) is None


def test_mismatched_job_identity_is_rejected() -> None:
    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(
            lambda _request: _json_response(
                [
                    _job(
                        sha="b" * 40,
                    )
                ]
            )
        ),
    )

    with pytest.raises(
        SecurityGateEvidenceError,
        match=r"\ASecurity gate evidence is unavailable\.\Z",
    ):
        asyncio.run(client.get_block_evidence(_event()))


@pytest.mark.parametrize(
    "trace",
    (
        (b"Security gate decision: BLOCK (3/2 blocking findings)\n"),
        (
            b"Security gate decision: BLOCK (1/2 blocking findings)\n"
            b"Security gate decision: BLOCK (1/2 blocking findings)\n"
        ),
        b"A" * (MAX_SECURITY_GATE_RESPONSE_BYTES + 1),
    ),
    ids=(
        "blocking-exceeds-total",
        "duplicate-marker",
        "oversized-trace",
    ),
)
def test_invalid_trace_is_rejected(trace: bytes) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jobs"):
            return _json_response([_job()])

        return httpx.Response(200, content=trace)

    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(
        SecurityGateEvidenceError,
        match=r"\ASecurity gate evidence is unavailable\.\Z",
    ):
        asyncio.run(client.get_block_evidence(_event()))


def test_network_failure_is_static_and_secret_safe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "DO-NOT-PROPAGATE",
            request=request,
        )

    client = GitLabSecurityGateEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(
        SecurityGateEvidenceError,
        match=r"\ASecurity gate evidence is unavailable\.\Z",
    ) as error:
        asyncio.run(client.get_block_evidence(_event()))

    assert _TOKEN not in str(error.value)
    assert "DO-NOT-PROPAGATE" not in str(error.value)

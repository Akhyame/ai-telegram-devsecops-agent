"""Offline security tests for GitLab Security Gate result retrieval."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from agent.security_models import (
    MAX_BLOCKING_DETAILS,
    NormalizedSecurityScan,
    SecurityFindingSummary,
    SecurityScanDecision,
    SecurityScanner,
    SecuritySeverity,
)
from bot.gitlab_client import (
    GitLabClientError,
    GitLabErrorKind,
)
from bot.gitlab_config import GitLabSettings
from bot.security_scan_results import (
    MAX_SECURITY_GATE_RESULT_BYTES,
    GitLabSecurityScanResultClient,
)

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = 123456
_PIPELINE_ID = 987654
_JOB_ID = 456789
_DEFAULT_REF = "main"
_VALID_SHA = "a" * 40


def _valid_token() -> str:
    return "".join(
        (
            "gl",
            "pat-",
            "R" * 24,
            ".",
            "S" * 24,
        )
    )


def _settings() -> GitLabSettings:
    return GitLabSettings(
        GITLAB_API_URL=_API_URL,
        GITLAB_PROJECT_ID=str(_PROJECT_ID),
        GITLAB_DEFAULT_REF=_DEFAULT_REF,
        GITLAB_API_TOKEN=_valid_token(),
    )


def _pipeline_payload(
    *,
    status: str = "success",
) -> dict[str, Any]:
    return {
        "id": _PIPELINE_ID,
        "project_id": _PROJECT_ID,
        "status": status,
        "ref": _DEFAULT_REF,
        "sha": _VALID_SHA,
    }


def _job_payload(
    *,
    job_id: object = _JOB_ID,
    name: object = "security_gate",
    stage: object = "security_gate",
    status: object = "success",
    ref: object = _DEFAULT_REF,
    pipeline_id: object = _PIPELINE_ID,
) -> dict[str, Any]:
    return {
        "id": job_id,
        "name": name,
        "stage": stage,
        "status": status,
        "ref": ref,
        "pipeline": {
            "id": pipeline_id,
        },
    }


def _gate_payload(
    *,
    decision: object = "allow",
    total_findings: object = 0,
    blocking_findings: object = 0,
    reasons: object = None,
    **extra: Any,
) -> dict[str, Any]:
    if reasons is None:
        reasons = []

    payload: dict[str, Any] = {
        "decision": decision,
        "total_findings": total_findings,
        "blocking_findings": blocking_findings,
        "reasons": reasons,
    }
    payload.update(extra)

    return payload


def _route(
    request: httpx.Request,
    *,
    pipeline_status: str = "success",
    jobs_payload: object | None = None,
    gate_payload: object | None = None,
) -> httpx.Response:
    path = request.url.path

    if path.endswith("/pipelines/latest"):
        return httpx.Response(
            200,
            json=_pipeline_payload(status=pipeline_status),
        )

    if path.endswith(f"/pipelines/{_PIPELINE_ID}/jobs"):
        if jobs_payload is None:
            jobs_payload = [_job_payload(status=pipeline_status)]

        return httpx.Response(
            200,
            json=jobs_payload,
        )

    if path.endswith(f"/jobs/{_JOB_ID}/artifacts/security-gate-result.json"):
        if gate_payload is None:
            gate_payload = _gate_payload()

        return httpx.Response(
            200,
            json=gate_payload,
        )

    raise AssertionError(f"Unexpected request path: {path}")


def _client(
    handler: Callable[
        [httpx.Request],
        httpx.Response,
    ],
) -> GitLabSecurityScanResultClient:
    return GitLabSecurityScanResultClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )


def _run(
    client: GitLabSecurityScanResultClient,
) -> NormalizedSecurityScan:
    return asyncio.run(client.get_latest_security_scan())


def test_exact_read_only_request_boundary_and_allowed_result() -> None:
    requests: list[httpx.Request] = []
    token = _valid_token()

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        requests.append(request)
        return _route(
            request,
            gate_payload=_gate_payload(total_findings=2),
        )

    scan = _run(_client(handler))

    assert len(requests) == 3

    latest_request = requests[0]
    jobs_request = requests[1]
    artifact_request = requests[2]

    assert latest_request.method == "GET"
    assert latest_request.url.path == ("/api/v4/projects/123456/pipelines/latest")
    assert len(latest_request.url.params) == 1
    assert latest_request.url.params["ref"] == "main"

    assert jobs_request.method == "GET"
    assert jobs_request.url.path == ("/api/v4/projects/123456/pipelines/987654/jobs")
    assert len(jobs_request.url.params) == 2
    assert jobs_request.url.params["include_retried"] == "false"
    assert jobs_request.url.params["per_page"] == "100"

    assert artifact_request.method == "GET"
    assert artifact_request.url.path == (
        "/api/v4/projects/123456/jobs/456789/artifacts/security-gate-result.json"
    )
    assert len(artifact_request.url.params) == 0

    for request in requests:
        assert request.headers["PRIVATE-TOKEN"] == token
        assert token not in str(request.url)

    assert scan == NormalizedSecurityScan(
        decision=SecurityScanDecision.ALLOW,
        total_findings=2,
        blocking_findings=0,
    )


@pytest.mark.parametrize(
    (
        "reason",
        "expected_severity",
    ),
    (
        (
            "semgrep:test.rule has blocked severity high",
            SecuritySeverity.HIGH,
        ),
        (
            "trivy-vulnerability:CVE-TEST has an unknown severity",
            SecuritySeverity.UNKNOWN,
        ),
    ),
)
def test_blocking_reasons_are_strictly_normalized(
    reason: str,
    expected_severity: SecuritySeverity,
) -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return _route(
            request,
            pipeline_status="failed",
            jobs_payload=[_job_payload(status="failed")],
            gate_payload=_gate_payload(
                decision="block",
                total_findings=3,
                blocking_findings=1,
                reasons=[reason],
            ),
        )

    scan = _run(_client(handler))

    assert scan.decision is SecurityScanDecision.BLOCK
    assert scan.blocking_findings == 1
    assert scan.blocking_details == (
        SecurityFindingSummary(
            source=(
                SecurityScanner.SEMGREP
                if reason.startswith("semgrep:")
                else SecurityScanner.TRIVY_VULNERABILITY
            ),
            rule_id=("test.rule" if reason.startswith("semgrep:") else "CVE-TEST"),
            severity=expected_severity,
        ),
    )
    assert scan.details_truncated is False


def test_blocking_details_are_bounded_and_marked_truncated() -> None:
    reasons = [
        (f"gitleaks:test-rule-{index} has blocked severity high")
        for index in range(MAX_BLOCKING_DETAILS + 1)
    ]

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return _route(
            request,
            pipeline_status="failed",
            jobs_payload=[_job_payload(status="failed")],
            gate_payload=_gate_payload(
                decision="block",
                total_findings=len(reasons),
                blocking_findings=len(reasons),
                reasons=reasons,
            ),
        )

    scan = _run(_client(handler))

    assert len(scan.blocking_details) == (MAX_BLOCKING_DETAILS)
    assert scan.details_truncated is True


@pytest.mark.parametrize(
    "status",
    (
        "created",
        "pending",
        "running",
        "canceled",
    ),
)
def test_non_terminal_or_non_evaluable_pipeline_is_rejected(
    status: str,
) -> None:
    request_count = 0

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            200,
            json=_pipeline_payload(status=status),
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert request_count == 1
    assert error.value.kind is (GitLabErrorKind.ACTION_NOT_ALLOWED)


@pytest.mark.parametrize(
    "jobs_payload",
    (
        [],
        [_job_payload(name="unit_tests")],
        [
            _job_payload(),
            _job_payload(job_id=_JOB_ID + 1),
        ],
        [_job_payload(job_id=0)],
        [_job_payload(stage="security")],
        [_job_payload(ref="other")],
        [_job_payload(pipeline_id=_PIPELINE_ID + 1)],
        [_job_payload(status="failed")],
    ),
)
def test_invalid_security_gate_job_is_rejected(
    jobs_payload: object,
) -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return _route(
            request,
            jobs_payload=jobs_payload,
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is (GitLabErrorKind.INVALID_RESPONSE)


@pytest.mark.parametrize(
    "gate_payload",
    (
        [],
        _gate_payload(extra_field="untrusted"),
        _gate_payload(decision="ALLOW"),
        _gate_payload(total_findings=True),
        _gate_payload(blocking_findings=True),
        _gate_payload(reasons="not-a-list"),
        _gate_payload(
            decision="block",
            total_findings=1,
            blocking_findings=1,
            reasons=[],
        ),
        _gate_payload(
            decision="block",
            total_findings=1,
            blocking_findings=1,
            reasons=["unknown-scanner:test-rule has blocked severity high"],
        ),
        _gate_payload(
            decision="block",
            total_findings=1,
            blocking_findings=1,
            reasons=["semgrep:unsafe rule has blocked severity high"],
        ),
        _gate_payload(
            decision="block",
            total_findings=1,
            blocking_findings=1,
            reasons=["semgrep:test-rule has blocked severity extreme"],
        ),
    ),
)
def test_invalid_gate_artifact_is_rejected(
    gate_payload: object,
) -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return _route(
            request,
            pipeline_status="failed",
            jobs_payload=[_job_payload(status="failed")],
            gate_payload=gate_payload,
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is (GitLabErrorKind.INVALID_RESPONSE)


def test_duplicate_artifact_keys_are_rejected() -> None:
    duplicate_body = (
        b'{"decision":"allow","decision":"block",'
        b'"total_findings":0,'
        b'"blocking_findings":0,"reasons":[]}'
    )

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith("security-gate-result.json"):
            return httpx.Response(
                200,
                content=duplicate_body,
                headers={"Content-Type": "application/json"},
            )

        return _route(request)

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is (GitLabErrorKind.INVALID_RESPONSE)


def test_pipeline_and_gate_decisions_must_agree() -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        return _route(
            request,
            gate_payload=_gate_payload(
                decision="block",
                total_findings=1,
                blocking_findings=1,
                reasons=["semgrep:test-rule has blocked severity high"],
            ),
        )

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is (GitLabErrorKind.INVALID_RESPONSE)


def test_artifact_redirect_does_not_forward_token() -> None:
    requests: list[httpx.Request] = []
    redirect_url = "https://cdn.artifacts.gitlab-static.net/controlled/security-gate-result.json"

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        requests.append(request)

        if (
            request.url.path.endswith("security-gate-result.json")
            and request.url.host == "gitlab.com"
        ):
            return httpx.Response(
                302,
                headers={"Location": redirect_url},
            )

        if request.url.host == ("cdn.artifacts.gitlab-static.net"):
            assert "PRIVATE-TOKEN" not in request.headers
            assert _valid_token() not in str(request.url)

            return httpx.Response(
                200,
                json=_gate_payload(),
            )

        return _route(request)

    scan = _run(_client(handler))

    assert scan.decision is SecurityScanDecision.ALLOW
    assert len(requests) == 4


@pytest.mark.parametrize(
    "location",
    (
        "http://cdn.artifacts.gitlab-static.net/file",
        "https://example.com/file",
        "https://127.0.0.1/file",
        "/relative/file",
    ),
)
def test_unsafe_artifact_redirect_is_rejected(
    location: str,
) -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith("security-gate-result.json"):
            return httpx.Response(
                302,
                headers={"Location": location},
            )

        return _route(request)

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is (GitLabErrorKind.INVALID_RESPONSE)


def test_oversized_artifact_is_rejected() -> None:
    body = b"x" * (MAX_SECURITY_GATE_RESULT_BYTES + 1)

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith("security-gate-result.json"):
            return httpx.Response(
                200,
                content=body,
                headers={"Content-Type": "application/json"},
            )

        return _route(request)

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is (GitLabErrorKind.INVALID_RESPONSE)


@pytest.mark.parametrize(
    (
        "status_code",
        "expected_kind",
    ),
    (
        (
            401,
            GitLabErrorKind.AUTHENTICATION,
        ),
        (
            403,
            GitLabErrorKind.ACCESS_OR_PIPELINE_MISSING,
        ),
        (
            404,
            GitLabErrorKind.PROJECT_NOT_FOUND,
        ),
        (
            429,
            GitLabErrorKind.RATE_LIMITED,
        ),
        (
            500,
            GitLabErrorKind.UPSTREAM,
        ),
    ),
)
def test_artifact_http_failures_are_controlled(
    status_code: int,
    expected_kind: GitLabErrorKind,
) -> None:
    sensitive_body = _valid_token() + " UNTRUSTED-UPSTREAM-BODY"

    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith("security-gate-result.json"):
            return httpx.Response(
                status_code,
                text=sensitive_body,
            )

        return _route(request)

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is expected_kind
    assert sensitive_body not in str(error.value)
    assert _valid_token() not in str(error.value)


def test_network_failure_is_controlled() -> None:
    def handler(
        request: httpx.Request,
    ) -> httpx.Response:
        if request.url.path.endswith(f"/pipelines/{_PIPELINE_ID}/jobs"):
            raise httpx.ReadTimeout(
                "UNTRUSTED-NETWORK-DETAIL",
                request=request,
            )

        return _route(request)

    with pytest.raises(
        GitLabClientError,
        match=r"\AGitLab request failed\.\Z",
    ) as error:
        _run(_client(handler))

    assert error.value.kind is GitLabErrorKind.NETWORK
    assert "UNTRUSTED-NETWORK-DETAIL" not in str(error.value)

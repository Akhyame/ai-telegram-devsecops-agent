"""Offline tests for bounded deployment evidence from GitLab job traces."""

import asyncio

import httpx
import pytest

from bot.gitlab_config import GitLabSettings
from sample_app.deployment_evidence import (
    MAX_DEPLOYMENT_TRACE_BYTES,
    DeploymentEnvironment,
    DeploymentEvidence,
    DeploymentEvidenceError,
    DeploymentResultStatus,
    GitLabDeploymentEvidenceClient,
    RollbackStatus,
)
from sample_app.webhook_events import (
    PipelineEventStatus,
    PipelineWebhookEvent,
)

_PROJECT_ID = 85705009
_PIPELINE_ID = 987654
_JOB_ID = 16_214_115_727
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
    status: PipelineEventStatus = PipelineEventStatus.SUCCESS,
) -> PipelineWebhookEvent:
    return PipelineWebhookEvent(
        pipeline_id=_PIPELINE_ID,
        status=status,
        ref="main",
        sha=_SHA,
    )


def _job(
    *,
    name: str = "deploy_staging",
    status: str = "success",
    sha: str = _SHA,
) -> dict[str, object]:
    return {
        "id": _JOB_ID,
        "name": name,
        "stage": "deploy",
        "status": status,
        "ref": "main",
        "pipeline": {
            "id": _PIPELINE_ID,
            "project_id": _PROJECT_ID,
            "ref": "main",
            "sha": sha,
        },
    }


def _client_for_trace(
    trace: bytes,
    *,
    job_name: str = "deploy_staging",
    job_status: str = "success",
) -> GitLabDeploymentEvidenceClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/jobs"):
            return httpx.Response(
                200,
                json=[
                    _job(
                        name=job_name,
                        status=job_status,
                    )
                ],
            )

        return httpx.Response(
            200,
            content=trace,
        )

    return GitLabDeploymentEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )


def test_successful_staging_deployment_is_normalized() -> None:
    client = _client_for_trace(b"DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n")

    evidence = asyncio.run(client.get_evidence(_event()))

    assert evidence == DeploymentEvidence(
        status=DeploymentResultStatus.DEPLOYED,
        environment=DeploymentEnvironment.STAGING,
        target_commit_sha=_SHA,
        rollback=RollbackStatus.NOT_REQUIRED,
    )


def test_successful_production_deployment_maps_environment() -> None:
    client = _client_for_trace(
        b"DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n",
        job_name="deploy_production",
    )

    evidence = asyncio.run(client.get_evidence(_event()))

    assert evidence is not None
    assert evidence.environment is DeploymentEnvironment.PRODUCTION


@pytest.mark.parametrize(
    ("trace", "expected_status", "expected_rollback"),
    (
        (
            b"DEPLOYMENT_RESULT=configuration_failed\n",
            DeploymentResultStatus.CONFIGURATION_FAILED,
            RollbackStatus.NOT_ATTEMPTED,
        ),
        (
            b"DEPLOYMENT_RESULT=previous_release_invalid\n",
            DeploymentResultStatus.PREVIOUS_RELEASE_INVALID,
            RollbackStatus.NOT_ATTEMPTED,
        ),
        (
            (b"DEPLOYMENT_RESULT=failed ROLLBACK=required\nROLLBACK_RESULT=unavailable\n"),
            DeploymentResultStatus.DEPLOYMENT_FAILED,
            RollbackStatus.UNAVAILABLE,
        ),
        (
            (b"DEPLOYMENT_RESULT=failed ROLLBACK=required\nROLLBACK_RESULT=succeeded\n"),
            DeploymentResultStatus.DEPLOYMENT_FAILED_ROLLED_BACK,
            RollbackStatus.SUCCEEDED,
        ),
        (
            (b"DEPLOYMENT_RESULT=failed ROLLBACK=required\nROLLBACK_RESULT=failed\n"),
            DeploymentResultStatus.ROLLBACK_FAILED,
            RollbackStatus.FAILED,
        ),
    ),
)
def test_failure_states_are_normalized(
    trace: bytes,
    expected_status: DeploymentResultStatus,
    expected_rollback: RollbackStatus,
) -> None:
    client = _client_for_trace(
        trace,
        job_status="failed",
    )

    evidence = asyncio.run(
        client.get_evidence(
            _event(PipelineEventStatus.FAILED),
        )
    )

    assert evidence is not None
    assert evidence.status is expected_status
    assert evidence.rollback is expected_rollback


def test_ansi_sequences_do_not_change_controlled_marker() -> None:
    client = _client_for_trace(b"\x1b[0KDEPLOYMENT_RESULT=deployed ROLLBACK=not_required\x1b[0m\n")

    evidence = asyncio.run(client.get_evidence(_event()))

    assert evidence is not None
    assert evidence.status is DeploymentResultStatus.DEPLOYED


def test_non_deployment_pipeline_returns_none_without_trace_request() -> None:
    request_count = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            200,
            json=[
                {
                    "id": 7,
                    "name": "unit_tests",
                }
            ],
        )

    client = GitLabDeploymentEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(client.get_evidence(_event())) is None
    assert request_count == 1


def test_non_terminal_deployment_job_performs_no_trace_request() -> None:
    request_count = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1

        return httpx.Response(
            200,
            json=[
                _job(
                    status="running",
                )
            ],
        )

    client = GitLabDeploymentEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(client.get_evidence(_event())) is None
    assert request_count == 1


def test_mismatched_pipeline_sha_fails_closed() -> None:
    client = GitLabDeploymentEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json=[
                    _job(
                        sha="b" * 40,
                    )
                ],
            )
        ),
    )

    with pytest.raises(
        DeploymentEvidenceError,
        match=r"\ADeployment evidence is unavailable\.\Z",
    ):
        asyncio.run(client.get_evidence(_event()))


def test_multiple_deployment_jobs_fail_closed() -> None:
    client = GitLabDeploymentEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json=[
                    _job(name="deploy_staging"),
                    _job(name="deploy_production"),
                ],
            )
        ),
    )

    with pytest.raises(
        DeploymentEvidenceError,
        match=r"\ADeployment evidence is unavailable\.\Z",
    ):
        asyncio.run(client.get_evidence(_event()))


@pytest.mark.parametrize(
    "trace",
    (
        b"unrelated output\n",
        (
            b"DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n"
            b"DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n"
        ),
        (
            b"DEPLOYMENT_RESULT=failed ROLLBACK=required\n"
            b"ROLLBACK_RESULT=succeeded\n"
            b"ROLLBACK_RESULT=failed\n"
        ),
        (b"DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\nROLLBACK_RESULT=succeeded\n"),
    ),
)
def test_invalid_marker_combinations_fail_closed(
    trace: bytes,
) -> None:
    client = _client_for_trace(
        trace,
        job_status="failed",
    )

    with pytest.raises(
        DeploymentEvidenceError,
        match=r"\ADeployment evidence is unavailable\.\Z",
    ):
        asyncio.run(
            client.get_evidence(
                _event(PipelineEventStatus.FAILED),
            )
        )


def test_oversized_trace_fails_closed() -> None:
    client = _client_for_trace(b"A" * (MAX_DEPLOYMENT_TRACE_BYTES + 1))

    with pytest.raises(
        DeploymentEvidenceError,
        match=r"\ADeployment evidence is unavailable\.\Z",
    ):
        asyncio.run(client.get_evidence(_event()))


def test_network_failure_is_static_and_secret_safe() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "DO-NOT-PROPAGATE",
            request=request,
        )

    client = GitLabDeploymentEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(
        DeploymentEvidenceError,
        match=r"\ADeployment evidence is unavailable\.\Z",
    ) as error:
        asyncio.run(client.get_evidence(_event()))

    assert _TOKEN not in str(error.value)
    assert "DO-NOT-PROPAGATE" not in str(error.value)


@pytest.mark.parametrize(
    "job_id",
    (
        0,
        -1,
        True,
    ),
)
def test_invalid_job_identifier_fails_closed(
    job_id: object,
) -> None:
    job = _job()
    job["id"] = job_id

    client = GitLabDeploymentEvidenceClient(
        _settings(),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json=[job],
            )
        ),
    )

    with pytest.raises(
        DeploymentEvidenceError,
        match=r"\ADeployment evidence is unavailable\.\Z",
    ):
        asyncio.run(client.get_evidence(_event()))


def test_gitlab_timestamp_prefix_is_removed_before_marker_validation() -> None:
    client = _client_for_trace(
        b"2026-08-31T19:09:23.794141Z 01O DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n"
    )

    evidence = asyncio.run(client.get_evidence(_event()))

    assert evidence is not None
    assert evidence.status is DeploymentResultStatus.DEPLOYED
    assert evidence.rollback is RollbackStatus.NOT_REQUIRED


def test_marker_without_gitlab_timestamp_prefix_remains_supported() -> None:
    client = _client_for_trace(b"DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n")

    evidence = asyncio.run(client.get_evidence(_event()))

    assert evidence is not None
    assert evidence.status is DeploymentResultStatus.DEPLOYED


@pytest.mark.parametrize(
    "trace",
    (
        (b"arbitrary-prefix DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n"),
        (b"2026-08-31 invalid-prefix DEPLOYMENT_RESULT=deployed ROLLBACK=not_required\n"),
    ),
)
def test_untrusted_prefix_cannot_spoof_deployment_marker(
    trace: bytes,
) -> None:
    client = _client_for_trace(trace)

    with pytest.raises(
        DeploymentEvidenceError,
        match=r"\ADeployment evidence is unavailable\.\Z",
    ):
        asyncio.run(client.get_evidence(_event()))

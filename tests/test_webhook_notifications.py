"""Offline tests for controlled Telegram pipeline notifications."""

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from bot.config import get_bot_settings
from sample_app.webhook_events import (
    PipelineEventStatus,
    PipelineWebhookEvent,
)
from sample_app.webhook_notifications import (
    MAX_TELEGRAM_RESPONSE_BYTES,
    NOTIFIABLE_PIPELINE_STATUSES,
    PipelineNotificationConfigurationError,
    PipelineNotificationDeliveryError,
    TelegramPipelineNotifier,
)

_ADMIN_ID = 123456789
_SECOND_ADMIN_ID = 987654321
_TOKEN = str(123_456_789) + ":" + ("A" * 32)


@pytest.fixture(autouse=True)
def _isolate_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)

    for name in (
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_ALLOWED_USER_IDS",
        "TELEGRAM_OPERATOR_USER_IDS",
        "TELEGRAM_ADMIN_USER_IDS",
    ):
        monkeypatch.delenv(name, raising=False)

    get_bot_settings.cache_clear()
    yield
    get_bot_settings.cache_clear()


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    *,
    admin_ids: str = str(_ADMIN_ID),
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _TOKEN)
    monkeypatch.setenv("TELEGRAM_ALLOWED_USER_IDS", admin_ids)
    monkeypatch.setenv("TELEGRAM_ADMIN_USER_IDS", admin_ids)


def _event(
    status: PipelineEventStatus = PipelineEventStatus.SUCCESS,
) -> PipelineWebhookEvent:
    return PipelineWebhookEvent(
        pipeline_id=987654,
        status=status,
        ref="main",
        sha="a" * 40,
    )


def _success_response() -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        json={"ok": True, "result": {}},
    )


def test_terminal_statuses_are_explicit() -> None:
    assert NOTIFIABLE_PIPELINE_STATUSES == frozenset(
        {
            PipelineEventStatus.SUCCESS,
            PipelineEventStatus.FAILED,
            PipelineEventStatus.CANCELED,
        }
    )


@pytest.mark.parametrize("status", tuple(NOTIFIABLE_PIPELINE_STATUSES))
def test_terminal_event_is_sent_as_protected_plain_text(
    monkeypatch: pytest.MonkeyPatch,
    status: PipelineEventStatus,
) -> None:
    _configure(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _success_response()

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    delivered = asyncio.run(notifier.send(_event(status)))

    assert delivered is True
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "POST"
    assert request.url.host == "api.telegram.org"
    assert request.url.path.endswith("/sendMessage")
    payload = json.loads(request.content)
    assert payload == {
        "chat_id": _ADMIN_ID,
        "text": (
            f"GitLab pipeline update.\nStatus: {status.value}.\nRef: main.\nCommit: aaaaaaaa."
        ),
        "link_preview_options": {
            "is_disabled": True,
        },
        "protect_content": True,
    }
    assert "parse_mode" not in payload
    assert len(payload["text"]) < 4_096


def test_intermediate_event_performs_no_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("Intermediate event attempted network access.")

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    delivered = asyncio.run(notifier.send(_event(PipelineEventStatus.RUNNING)))

    assert delivered is False


def test_each_configured_admin_receives_one_notification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(
        monkeypatch,
        admin_ids=f"{_ADMIN_ID},{_SECOND_ADMIN_ID}",
    )
    chat_ids: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        chat_ids.append(json.loads(request.content)["chat_id"])
        return _success_response()

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(notifier.send(_event())) is True
    assert chat_ids == [_ADMIN_ID, _SECOND_ADMIN_ID]


def test_missing_admin_destination_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _TOKEN)

    with pytest.raises(
        PipelineNotificationConfigurationError,
        match=r"\ATelegram notification configuration is invalid\.\Z",
    ):
        TelegramPipelineNotifier(get_bot_settings())


@pytest.mark.parametrize(
    "response",
    (
        httpx.Response(500, text="DO-NOT-PROPAGATE"),
        httpx.Response(200, json={"ok": False}),
        httpx.Response(200, content=b"invalid-json"),
        httpx.Response(
            200,
            content=b"A" * (MAX_TELEGRAM_RESPONSE_BYTES + 1),
        ),
    ),
)
def test_invalid_telegram_response_is_static(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
) -> None:
    _configure(monkeypatch)

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(lambda _request: response),
    )

    with pytest.raises(
        PipelineNotificationDeliveryError,
        match=r"\ATelegram notification delivery failed\.\Z",
    ) as error:
        asyncio.run(notifier.send(_event()))

    assert _TOKEN not in str(error.value)
    assert "DO-NOT-PROPAGATE" not in str(error.value)


def test_delivery_failure_is_logged_without_secret_or_detail(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _configure(monkeypatch)


def test_block_evidence_sends_minimized_security_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sample_app.security_gate_evidence import SecurityGateBlockEvidence

    _configure(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _success_response()

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )
    evidence = SecurityGateBlockEvidence(
        blocking_findings=2,
        total_findings=7,
    )

    delivered = asyncio.run(
        notifier.send(
            _event(PipelineEventStatus.FAILED),
            evidence=evidence,
        )
    )

    assert delivered is True
    assert len(requests) == 1
    payload = json.loads(requests[0].content)
    assert payload == {
        "chat_id": _ADMIN_ID,
        "text": (
            "GitLab security alert.\n"
            "Detected security findings violated the policy.\n"
            "Blocking findings: 2.\n"
            "Total findings: 7.\n"
            "Ref: main.\n"
            "Commit: aaaaaaaa."
        ),
        "link_preview_options": {
            "is_disabled": True,
        },
        "protect_content": True,
    }
    assert "reasons" not in payload["text"].lower()
    assert len(payload["text"]) < 4_096


def test_notify_pipeline_event_passes_resolved_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    import sample_app.webhook_notifications as notifications
    from sample_app.security_gate_evidence import SecurityGateBlockEvidence

    _configure(monkeypatch)
    event = _event(PipelineEventStatus.FAILED)
    evidence = SecurityGateBlockEvidence(
        blocking_findings=1,
        total_findings=3,
    )
    resolver = AsyncMock(return_value=evidence)
    sender = AsyncMock(return_value=True)
    notifier = SimpleNamespace(send=sender)

    monkeypatch.setattr(
        notifications,
        "_resolve_security_gate_evidence",
        resolver,
    )
    monkeypatch.setattr(
        notifications,
        "_build_pipeline_notifier",
        lambda _settings: notifier,
    )

    assert asyncio.run(notifications.notify_pipeline_event(event)) is True
    resolver.assert_awaited_once_with(event)
    sender.assert_awaited_once_with(
        event,
        evidence=evidence,
    )


def test_non_failed_event_skips_gate_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sample_app.webhook_notifications as notifications

    def fail_if_called() -> object:
        raise AssertionError("Non-failed event loaded GitLab settings.")

    monkeypatch.setattr(
        notifications,
        "get_gitlab_settings",
        fail_if_called,
    )

    evidence = asyncio.run(
        notifications._resolve_security_gate_evidence(_event(PipelineEventStatus.SUCCESS))
    )

    assert evidence is None


def test_gate_configuration_failure_is_generic(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import sample_app.webhook_notifications as notifications
    from bot.gitlab_config import GitLabConfigurationError

    def reject_configuration() -> object:
        raise GitLabConfigurationError("DO-NOT-PROPAGATE")

    monkeypatch.setattr(
        notifications,
        "get_gitlab_settings",
        reject_configuration,
    )

    evidence = asyncio.run(
        notifications._resolve_security_gate_evidence(_event(PipelineEventStatus.FAILED))
    )

    assert evidence is None
    assert notifications.SECURITY_GATE_EVIDENCE_FAILURE_LOG in caplog.text
    assert "DO-NOT-PROPAGATE" not in caplog.text


def test_deployment_success_sends_minimized_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sample_app.deployment_evidence import (
        DeploymentEnvironment,
        DeploymentEvidence,
        DeploymentResultStatus,
        RollbackStatus,
    )

    _configure(monkeypatch)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _success_response()

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(handler),
    )

    evidence = DeploymentEvidence(
        status=DeploymentResultStatus.DEPLOYED,
        environment=DeploymentEnvironment.STAGING,
        target_commit_sha="a" * 40,
        rollback=RollbackStatus.NOT_REQUIRED,
    )

    assert (
        asyncio.run(
            notifier.send(
                _event(PipelineEventStatus.SUCCESS),
                deployment_evidence=evidence,
            )
        )
        is True
    )

    payload = json.loads(requests[0].content)

    assert payload["text"] == (
        "Deployment update.\n"
        "Environment: staging.\n"
        "Status: deployed.\n"
        "Health verification: passed.\n"
        "Commit: aaaaaaaa."
    )
    assert "pipeline" not in payload["text"].lower()
    assert "host" not in payload["text"].lower()
    assert "token" not in payload["text"].lower()


def test_successful_rollback_sends_recovery_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sample_app.deployment_evidence import (
        DeploymentEnvironment,
        DeploymentEvidence,
        DeploymentResultStatus,
        RollbackStatus,
    )

    _configure(monkeypatch)
    requests: list[httpx.Request] = []

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or _success_response()
        ),
    )

    evidence = DeploymentEvidence(
        status=DeploymentResultStatus.DEPLOYMENT_FAILED_ROLLED_BACK,
        environment=DeploymentEnvironment.STAGING,
        target_commit_sha="a" * 40,
        rollback=RollbackStatus.SUCCEEDED,
    )

    assert (
        asyncio.run(
            notifier.send(
                _event(PipelineEventStatus.FAILED),
                deployment_evidence=evidence,
            )
        )
        is True
    )

    payload = json.loads(requests[0].content)

    assert payload["text"] == (
        "Deployment alert.\n"
        "Environment: staging.\n"
        "Status: deployment failed.\n"
        "Rollback: succeeded.\n"
        "Restored release verification: passed.\n"
        "Commit: aaaaaaaa."
    )


def test_failed_rollback_sends_critical_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sample_app.deployment_evidence import (
        DeploymentEnvironment,
        DeploymentEvidence,
        DeploymentResultStatus,
        RollbackStatus,
    )

    _configure(monkeypatch)
    requests: list[httpx.Request] = []

    notifier = TelegramPipelineNotifier(
        get_bot_settings(),
        transport=httpx.MockTransport(
            lambda request: requests.append(request) or _success_response()
        ),
    )

    evidence = DeploymentEvidence(
        status=DeploymentResultStatus.ROLLBACK_FAILED,
        environment=DeploymentEnvironment.PRODUCTION,
        target_commit_sha="a" * 40,
        rollback=RollbackStatus.FAILED,
    )

    assert (
        asyncio.run(
            notifier.send(
                _event(PipelineEventStatus.FAILED),
                deployment_evidence=evidence,
            )
        )
        is True
    )

    payload = json.loads(requests[0].content)

    assert payload["text"] == (
        "Deployment critical alert.\n"
        "Environment: production.\n"
        "Status: deployment failed.\n"
        "Rollback: failed.\n"
        "Commit: aaaaaaaa."
    )


def test_notify_pipeline_event_prefers_deployment_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    import sample_app.webhook_notifications as notifications
    from sample_app.deployment_evidence import (
        DeploymentEnvironment,
        DeploymentEvidence,
        DeploymentResultStatus,
        RollbackStatus,
    )

    _configure(monkeypatch)

    event = _event(PipelineEventStatus.FAILED)
    deployment_evidence = DeploymentEvidence(
        status=DeploymentResultStatus.DEPLOYMENT_FAILED_ROLLED_BACK,
        environment=DeploymentEnvironment.STAGING,
        target_commit_sha="a" * 40,
        rollback=RollbackStatus.SUCCEEDED,
    )

    deployment_resolver = AsyncMock(return_value=deployment_evidence)
    gate_resolver = AsyncMock()
    sender = AsyncMock(return_value=True)
    notifier = SimpleNamespace(send=sender)

    monkeypatch.setattr(
        notifications,
        "_resolve_deployment_evidence",
        deployment_resolver,
    )
    monkeypatch.setattr(
        notifications,
        "_resolve_security_gate_evidence",
        gate_resolver,
    )
    monkeypatch.setattr(
        notifications,
        "_build_pipeline_notifier",
        lambda _settings: notifier,
    )

    assert asyncio.run(notifications.notify_pipeline_event(event)) is True

    deployment_resolver.assert_awaited_once_with(event)
    gate_resolver.assert_not_awaited()
    sender.assert_awaited_once_with(
        event,
        deployment_evidence=deployment_evidence,
    )


def test_non_deployment_pipeline_falls_back_to_security_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    import sample_app.webhook_notifications as notifications
    from sample_app.security_gate_evidence import (
        SecurityGateBlockEvidence,
    )

    _configure(monkeypatch)

    event = _event(PipelineEventStatus.FAILED)
    security_evidence = SecurityGateBlockEvidence(
        blocking_findings=2,
        total_findings=5,
    )

    deployment_resolver = AsyncMock(return_value=None)
    gate_resolver = AsyncMock(return_value=security_evidence)
    sender = AsyncMock(return_value=True)
    notifier = SimpleNamespace(send=sender)

    monkeypatch.setattr(
        notifications,
        "_resolve_deployment_evidence",
        deployment_resolver,
    )
    monkeypatch.setattr(
        notifications,
        "_resolve_security_gate_evidence",
        gate_resolver,
    )
    monkeypatch.setattr(
        notifications,
        "_build_pipeline_notifier",
        lambda _settings: notifier,
    )

    assert asyncio.run(notifications.notify_pipeline_event(event)) is True

    deployment_resolver.assert_awaited_once_with(event)
    gate_resolver.assert_awaited_once_with(event)
    sender.assert_awaited_once_with(
        event,
        evidence=security_evidence,
    )


def test_deployment_evidence_failure_is_generic(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import sample_app.webhook_notifications as notifications
    from bot.gitlab_config import GitLabConfigurationError

    def reject_configuration() -> object:
        raise GitLabConfigurationError("DO-NOT-PROPAGATE")

    monkeypatch.setattr(
        notifications,
        "get_gitlab_settings",
        reject_configuration,
    )

    evidence = asyncio.run(
        notifications._resolve_deployment_evidence(_event(PipelineEventStatus.SUCCESS))
    )

    assert evidence is None
    assert notifications.DEPLOYMENT_EVIDENCE_FAILURE_LOG in caplog.text
    assert "DO-NOT-PROPAGATE" not in caplog.text

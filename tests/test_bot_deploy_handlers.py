"""Offline security tests for confirmed Telegram deployments."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import httpx
import pytest

import bot.deploy_handlers as deploy_handlers
import bot.handlers as base_handlers
from bot.action_audit import ActionAuditOutcome, emit_action_audit
from bot.action_confirmation import (
    ActionConfirmationStore,
    ActionKind,
    ActionTarget,
)
from bot.gitlab_client import (
    GitLabClientError,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_write_client import GitLabWriteClient
from bot.gitlab_write_config import GitLabWriteSettings
from deployment.models import DeploymentEnvironment

_ADMIN_USER_ID = 404
_PROJECT_ID = 123456
_REF = "main"
_TOKEN = "A" * 32
_SHA = "abcdef0123456789abcdef0123456789abcdef01"


def _valid_write_token() -> str:
    return "".join(("gl", "pat-", "W" * 48))


def _settings() -> GitLabWriteSettings:
    return GitLabWriteSettings(
        GITLAB_API_URL="https://gitlab.com/api/v4",
        GITLAB_PROJECT_ID=str(_PROJECT_ID),
        GITLAB_DEFAULT_REF=_REF,
        GITLAB_WRITE_API_TOKEN=_valid_write_token(),
    )


def _summary() -> PipelineSummary:
    return PipelineSummary(
        pipeline_id=654321,
        status=PipelineStatus.CREATED,
        ref=_REF,
        sha=_SHA,
    )


def _update(
    *,
    callback_data: str | None = None,
) -> tuple[SimpleNamespace, AsyncMock, SimpleNamespace | None]:
    message = AsyncMock()
    query = None

    if callback_data is not None:
        query = SimpleNamespace(
            data=callback_data,
            answer=AsyncMock(),
        )

    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=_ADMIN_USER_ID),
        callback_query=query,
    )
    return update, message, query


def _authorize(
    monkeypatch: pytest.MonkeyPatch,
    message: AsyncMock,
) -> AsyncMock:
    authorized = AsyncMock(return_value=message)
    monkeypatch.setattr(
        base_handlers,
        "_authorized_message",
        authorized,
    )
    return authorized


def _store(
    monkeypatch: pytest.MonkeyPatch,
) -> ActionConfirmationStore:
    store = ActionConfirmationStore(token_factory=lambda: _TOKEN)
    monkeypatch.setattr(
        deploy_handlers,
        "action_confirmation_store",
        store,
    )
    return store


def _target(
    environment: DeploymentEnvironment,
) -> ActionTarget:
    return ActionTarget(
        project_id=_PROJECT_ID,
        ref=_REF,
        environment=environment,
    )


def test_request_requires_one_exact_staging_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update, message, _ = _update()
    _authorize(monkeypatch, message)
    settings = Mock()
    monkeypatch.setattr(
        deploy_handlers,
        "get_gitlab_write_settings",
        settings,
    )

    for args in ([], ["STAGING"], ["production"], ["staging", "production"]):
        message.reset_mock()
        asyncio.run(
            deploy_handlers.deploy_handler(
                update,
                SimpleNamespace(args=args),
            )
        )
        assert message.reply_text.await_args.args[0] == deploy_handlers.DEPLOY_USAGE_MESSAGE

    settings.assert_not_called()


def test_request_issues_environment_bound_confirmation_without_gitlab_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update, message, _ = _update()
    authorized = _authorize(monkeypatch, message)
    store = _store(monkeypatch)
    audit = Mock()
    build_client = Mock()
    monkeypatch.setattr(
        deploy_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(deploy_handlers, "emit_action_audit", audit)
    monkeypatch.setattr(
        deploy_handlers,
        "_build_gitlab_write_client",
        build_client,
    )

    asyncio.run(
        deploy_handlers.deploy_handler(
            update,
            SimpleNamespace(args=["staging"]),
        )
    )

    authorized.assert_awaited_once_with(
        update,
        deploy_handlers.BotCommand.DEPLOY,
    )
    build_client.assert_not_called()
    assert store.pending_count == 1
    reply = message.reply_text.await_args
    button = reply.kwargs["reply_markup"].inline_keyboard[0][0]
    assert button.callback_data == f"deploy:staging:{_TOKEN}"
    assert "staging" in reply.args[0]
    audit.assert_called_once_with(
        user_id=_ADMIN_USER_ID,
        action=ActionKind.DEPLOY,
        outcome=ActionAuditOutcome.REQUESTED,
        target=_target(DeploymentEnvironment.STAGING),
    )


def test_staging_command_alias_requests_staging_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update, message, _query = _update()
    _authorize(monkeypatch, message)
    store = _store(monkeypatch)
    audit = Mock()
    build_client = Mock()
    monkeypatch.setattr(
        deploy_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(deploy_handlers, "emit_action_audit", audit)
    monkeypatch.setattr(
        deploy_handlers,
        "_build_gitlab_write_client",
        build_client,
    )

    asyncio.run(deploy_handlers.deploy_staging_handler(update, object()))

    build_client.assert_not_called()
    assert store.pending_count == 1
    reply = message.reply_text.await_args
    button = reply.kwargs["reply_markup"].inline_keyboard[0][0]
    assert button.callback_data == f"deploy:staging:{_TOKEN}"
    assert "staging" in reply.args[0]
    audit.assert_called_once_with(
        user_id=_ADMIN_USER_ID,
        action=ActionKind.DEPLOY,
        outcome=ActionAuditOutcome.REQUESTED,
        target=_target(DeploymentEnvironment.STAGING),
    )


def test_confirmation_executes_once_and_replay_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    callback_data = f"deploy:staging:{_TOKEN}"
    update, message, query = _update(callback_data=callback_data)
    _authorize(monkeypatch, message)
    store = _store(monkeypatch)
    store.issue(
        user_id=_ADMIN_USER_ID,
        action=ActionKind.DEPLOY,
        target=_target(DeploymentEnvironment.STAGING),
    )
    audit = Mock()
    client = SimpleNamespace(
        run_deployment=AsyncMock(return_value=_summary()),
    )
    monkeypatch.setattr(
        deploy_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(deploy_handlers, "emit_action_audit", audit)
    monkeypatch.setattr(
        deploy_handlers,
        "_build_gitlab_write_client",
        Mock(return_value=client),
    )

    asyncio.run(
        deploy_handlers.deploy_confirmation_handler(
            update,
            object(),
        )
    )

    assert query is not None
    query.answer.assert_awaited_once_with()
    client.run_deployment.assert_awaited_once_with(
        DeploymentEnvironment.STAGING,
    )
    assert _SHA not in message.reply_text.await_args.args[0]
    assert _SHA[:8] in message.reply_text.await_args.args[0]
    assert audit.call_args_list == [
        call(
            user_id=_ADMIN_USER_ID,
            action=ActionKind.DEPLOY,
            outcome=ActionAuditOutcome.CONFIRMED,
            target=_target(DeploymentEnvironment.STAGING),
        ),
        call(
            user_id=_ADMIN_USER_ID,
            action=ActionKind.DEPLOY,
            outcome=ActionAuditOutcome.SUCCEEDED,
            target=_target(DeploymentEnvironment.STAGING),
        ),
    ]

    asyncio.run(
        deploy_handlers.deploy_confirmation_handler(
            update,
            object(),
        )
    )

    client.run_deployment.assert_awaited_once()
    assert message.reply_text.await_args.args[0] == (
        deploy_handlers.DEPLOY_INVALID_CONFIRMATION_MESSAGE
    )
    assert audit.call_args_list[-1] == call(
        user_id=_ADMIN_USER_ID,
        action=ActionKind.DEPLOY,
        outcome=ActionAuditOutcome.DENIED,
        target=_target(DeploymentEnvironment.STAGING),
    )


def test_production_callback_is_rejected_before_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update, message, _ = _update(
        callback_data=f"deploy:production:{_TOKEN}",
    )
    _authorize(monkeypatch, message)
    store = _store(monkeypatch)
    store.issue(
        user_id=_ADMIN_USER_ID,
        action=ActionKind.DEPLOY,
        target=_target(DeploymentEnvironment.STAGING),
    )
    build_client = Mock()
    monkeypatch.setattr(
        deploy_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(
        deploy_handlers,
        "_build_gitlab_write_client",
        build_client,
    )
    monkeypatch.setattr(
        deploy_handlers,
        "emit_action_audit",
        Mock(),
    )

    asyncio.run(
        deploy_handlers.deploy_confirmation_handler(
            update,
            object(),
        )
    )

    build_client.assert_not_called()
    assert store.pending_count == 1
    assert message.reply_text.await_args.args[0] == (
        deploy_handlers.DEPLOY_INVALID_CONFIRMATION_MESSAGE
    )


def test_write_client_uses_exact_typed_deployment_inputs() -> None:
    token = _settings().api_token.get_secret_value()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/v4/projects/123456/pipeline"
        assert len(request.url.params) == 0
        assert request.headers["PRIVATE-TOKEN"] == token
        assert request.read() == (
            b'{"ref":"main","inputs":{"pipeline_profile":"full",'
            b'"deployment_environment":"staging"}}'
        )
        return httpx.Response(
            201,
            json={
                "id": 654321,
                "project_id": _PROJECT_ID,
                "status": "created",
                "ref": _REF,
                "sha": _SHA,
            },
        )

    client = GitLabWriteClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )
    summary = asyncio.run(client.run_deployment(DeploymentEnvironment.STAGING))

    assert summary.pipeline_id == 654321
    assert summary.ref == _REF


def test_write_client_rejects_production_before_network() -> None:
    transport = AsyncMock()
    client = GitLabWriteClient(
        _settings(),
        transport=transport,
    )

    with pytest.raises(GitLabClientError):
        asyncio.run(client.run_deployment(DeploymentEnvironment.PRODUCTION))

    transport.handle_async_request.assert_not_awaited()


def test_write_client_rejects_untyped_environment_before_network() -> None:
    transport = AsyncMock()
    client = GitLabWriteClient(
        _settings(),
        transport=transport,
    )

    with pytest.raises(GitLabClientError):
        asyncio.run(client.run_deployment("staging"))  # type: ignore[arg-type]

    transport.handle_async_request.assert_not_awaited()


def test_deployment_audit_records_exact_environment(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="bot.action_audit"):
        emit_action_audit(
            user_id=_ADMIN_USER_ID,
            action=ActionKind.DEPLOY,
            outcome=ActionAuditOutcome.REQUESTED,
            target=_target(DeploymentEnvironment.STAGING),
        )

    record = caplog.records[-1]
    assert record.audit_action == "deploy"
    assert record.audit_environment == "staging"

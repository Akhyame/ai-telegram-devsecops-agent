"""Offline security tests for confirmed Telegram pipeline launches."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest

import bot.handlers as base_handlers
import bot.run_pipeline_handlers as run_handlers
from bot.action_audit import ActionAuditOutcome
from bot.action_confirmation import (
    ActionConfirmationStore,
    ActionKind,
    ActionTarget,
)
from bot.gitlab_client import (
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_write_config import GitLabWriteConfigurationError

_OPERATOR_USER_ID = 202
_SECOND_OPERATOR_USER_ID = 303
_VIEWER_USER_ID = 101
_PROJECT_ID = 123456
_REF = "main"
_TOKEN = "A" * 32
_FULL_SHA = "abcdef0123456789abcdef0123456789abcdef01"


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        project_id=_PROJECT_ID,
        allowed_ref=_REF,
    )


def _target() -> ActionTarget:
    return ActionTarget(
        project_id=_PROJECT_ID,
        ref=_REF,
    )


def _summary() -> PipelineSummary:
    return PipelineSummary(
        pipeline_id=987654,
        status=PipelineStatus.PENDING,
        ref=_REF,
        sha=_FULL_SHA,
    )


def _configure_authorization(
    monkeypatch: pytest.MonkeyPatch,
    *,
    allowed_user_ids: frozenset[int],
    operator_user_ids: frozenset[int],
) -> None:
    settings = SimpleNamespace(
        allowed_user_ids=allowed_user_ids,
        operator_user_ids=operator_user_ids,
        admin_user_ids=frozenset(),
    )
    monkeypatch.setattr(
        base_handlers,
        "get_bot_settings",
        lambda: settings,
    )


def _request_update(
    user_id: int,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    message = SimpleNamespace(reply_text=AsyncMock())
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=user_id),
        effective_message=message,
        callback_query=None,
    )
    return update, message


def _callback_update(
    user_id: int,
    callback_data: object,
) -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    message = SimpleNamespace(reply_text=AsyncMock())
    query = SimpleNamespace(
        data=callback_data,
        answer=AsyncMock(),
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=user_id),
        effective_message=message,
        callback_query=query,
    )
    return update, message, query


def _install_store(
    monkeypatch: pytest.MonkeyPatch,
) -> ActionConfirmationStore:
    store = ActionConfirmationStore(token_factory=lambda: _TOKEN)
    monkeypatch.setattr(
        run_handlers,
        "action_confirmation_store",
        store,
    )
    return store


def test_viewer_is_denied_before_write_configuration_or_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=frozenset({_VIEWER_USER_ID}),
        operator_user_ids=frozenset(),
    )
    get_write_settings = Mock()
    build_client = Mock()
    audit = Mock()
    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        get_write_settings,
    )
    monkeypatch.setattr(
        run_handlers,
        "_build_gitlab_write_client",
        build_client,
    )
    monkeypatch.setattr(run_handlers, "emit_action_audit", audit)
    update, message = _request_update(_VIEWER_USER_ID)

    asyncio.run(run_handlers.run_pipeline_handler(update, object()))

    message.reply_text.assert_awaited_once_with(base_handlers.ACCESS_DENIED_MESSAGE)
    get_write_settings.assert_not_called()
    build_client.assert_not_called()
    audit.assert_not_called()


def test_authorized_request_issues_confirmation_without_gitlab_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=frozenset({_OPERATOR_USER_ID}),
    )
    store = _install_store(monkeypatch)
    settings = _settings()
    audit = Mock()
    build_client = Mock()
    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        lambda: settings,
    )
    monkeypatch.setattr(run_handlers, "emit_action_audit", audit)
    monkeypatch.setattr(
        run_handlers,
        "_build_gitlab_write_client",
        build_client,
    )
    update, message = _request_update(_OPERATOR_USER_ID)

    asyncio.run(run_handlers.run_pipeline_handler(update, object()))

    build_client.assert_not_called()
    assert store.pending_count == 1
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        outcome=ActionAuditOutcome.REQUESTED,
        target=_target(),
    )

    message.reply_text.assert_awaited_once()
    reply = message.reply_text.await_args
    text = reply.args[0]
    button = reply.kwargs["reply_markup"].inline_keyboard[0][0]

    assert text == ("Confirm launching the allowed GitLab pipeline within 2 minutes. Ref: main.")
    assert _TOKEN not in text
    assert str(_PROJECT_ID) not in text
    assert button.text == run_handlers.RUN_PIPELINE_CONFIRMATION_BUTTON
    assert button.callback_data == (f"{run_handlers.RUN_PIPELINE_CALLBACK_PREFIX}{_TOKEN}")
    assert reply.kwargs["protect_content"] is True


def test_configuration_failure_is_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=frozenset({_OPERATOR_USER_ID}),
    )
    sensitive_detail = "DO-NOT-LEAK-WRITE-CONFIG"

    def fail_configuration() -> None:
        raise GitLabWriteConfigurationError(sensitive_detail)

    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        fail_configuration,
    )
    update, message = _request_update(_OPERATOR_USER_ID)

    with caplog.at_level(logging.ERROR, logger="bot.run_pipeline_handlers"):
        asyncio.run(run_handlers.run_pipeline_handler(update, object()))

    message.reply_text.assert_awaited_once_with(run_handlers.RUN_PIPELINE_UNAVAILABLE_MESSAGE)
    assert run_handlers.RUN_PIPELINE_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text
    assert str(_OPERATOR_USER_ID) not in caplog.text


def test_matching_confirmation_launches_exactly_one_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=frozenset({_OPERATOR_USER_ID}),
    )
    store = _install_store(monkeypatch)
    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )
    settings = _settings()
    client = SimpleNamespace(run_pipeline=AsyncMock(return_value=_summary()))
    build_client = Mock(return_value=client)
    audit = Mock()
    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        lambda: settings,
    )
    monkeypatch.setattr(
        run_handlers,
        "_build_gitlab_write_client",
        build_client,
    )
    monkeypatch.setattr(run_handlers, "emit_action_audit", audit)
    update, message, query = _callback_update(
        _OPERATOR_USER_ID,
        f"{run_handlers.RUN_PIPELINE_CALLBACK_PREFIX}{token}",
    )

    asyncio.run(
        run_handlers.run_pipeline_confirmation_handler(
            update,
            object(),
        )
    )

    query.answer.assert_awaited_once_with()
    build_client.assert_called_once_with(settings)
    client.run_pipeline.assert_awaited_once_with()
    assert store.pending_count == 0

    audit.assert_has_calls(
        [
            call(
                user_id=_OPERATOR_USER_ID,
                action=ActionKind.RUN_PIPELINE,
                outcome=ActionAuditOutcome.CONFIRMED,
                target=_target(),
            ),
            call(
                user_id=_OPERATOR_USER_ID,
                action=ActionKind.RUN_PIPELINE,
                outcome=ActionAuditOutcome.SUCCEEDED,
                target=_target(),
            ),
        ]
    )

    reply = message.reply_text.await_args.args[0]
    assert reply == (
        "GitLab pipeline launch accepted. Status: pending. Ref: main. Commit: abcdef01."
    )
    assert _TOKEN not in reply
    assert _FULL_SHA not in reply
    assert "987654" not in reply
    assert str(_PROJECT_ID) not in reply


def test_confirmation_replay_does_not_launch_second_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=frozenset({_OPERATOR_USER_ID}),
    )
    store = _install_store(monkeypatch)
    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )
    settings = _settings()
    client = SimpleNamespace(run_pipeline=AsyncMock(return_value=_summary()))
    audit = Mock()
    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        lambda: settings,
    )
    monkeypatch.setattr(
        run_handlers,
        "_build_gitlab_write_client",
        Mock(return_value=client),
    )
    monkeypatch.setattr(run_handlers, "emit_action_audit", audit)
    update, message, query = _callback_update(
        _OPERATOR_USER_ID,
        f"{run_handlers.RUN_PIPELINE_CALLBACK_PREFIX}{token}",
    )

    asyncio.run(run_handlers.run_pipeline_confirmation_handler(update, object()))
    asyncio.run(run_handlers.run_pipeline_confirmation_handler(update, object()))

    assert query.answer.await_count == 2
    client.run_pipeline.assert_awaited_once_with()
    assert message.reply_text.await_count == 2
    assert (
        message.reply_text.await_args_list[1].args[0]
        == run_handlers.RUN_PIPELINE_INVALID_CONFIRMATION_MESSAGE
    )
    assert audit.call_args_list[-1] == call(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        outcome=ActionAuditOutcome.DENIED,
        target=_target(),
    )


def test_wrong_operator_cannot_consume_owner_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operators = frozenset({_OPERATOR_USER_ID, _SECOND_OPERATOR_USER_ID})
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=operators,
        operator_user_ids=operators,
    )
    store = _install_store(monkeypatch)
    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )
    settings = _settings()
    client = SimpleNamespace(run_pipeline=AsyncMock(return_value=_summary()))
    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        lambda: settings,
    )
    monkeypatch.setattr(
        run_handlers,
        "_build_gitlab_write_client",
        Mock(return_value=client),
    )
    monkeypatch.setattr(run_handlers, "emit_action_audit", Mock())

    wrong_update, wrong_message, _ = _callback_update(
        _SECOND_OPERATOR_USER_ID,
        f"{run_handlers.RUN_PIPELINE_CALLBACK_PREFIX}{token}",
    )
    asyncio.run(
        run_handlers.run_pipeline_confirmation_handler(
            wrong_update,
            object(),
        )
    )

    wrong_message.reply_text.assert_awaited_once()
    assert store.pending_count == 1
    client.run_pipeline.assert_not_awaited()

    owner_update, _, _ = _callback_update(
        _OPERATOR_USER_ID,
        f"{run_handlers.RUN_PIPELINE_CALLBACK_PREFIX}{token}",
    )
    asyncio.run(
        run_handlers.run_pipeline_confirmation_handler(
            owner_update,
            object(),
        )
    )

    client.run_pipeline.assert_awaited_once_with()
    assert store.pending_count == 0


def test_invalid_callback_is_denied_without_gitlab_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=frozenset({_OPERATOR_USER_ID}),
    )
    _install_store(monkeypatch)
    settings = _settings()
    build_client = Mock()
    audit = Mock()
    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        lambda: settings,
    )
    monkeypatch.setattr(
        run_handlers,
        "_build_gitlab_write_client",
        build_client,
    )
    monkeypatch.setattr(run_handlers, "emit_action_audit", audit)
    update, message, _ = _callback_update(
        _OPERATOR_USER_ID,
        "run_pipeline:not-valid",
    )

    asyncio.run(run_handlers.run_pipeline_confirmation_handler(update, object()))

    build_client.assert_not_called()
    message.reply_text.assert_awaited_once()
    assert (
        message.reply_text.await_args.args[0]
        == run_handlers.RUN_PIPELINE_INVALID_CONFIRMATION_MESSAGE
    )
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        outcome=ActionAuditOutcome.DENIED,
        target=_target(),
    )


def test_gitlab_failure_is_generic_redacted_and_audited(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _configure_authorization(
        monkeypatch,
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=frozenset({_OPERATOR_USER_ID}),
    )
    store = _install_store(monkeypatch)
    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        target=_target(),
    )
    sensitive_detail = "DO-NOT-LEAK-GITLAB-WRITE"

    async def fail_safely() -> PipelineSummary:
        try:
            raise RuntimeError(sensitive_detail)
        except RuntimeError as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc

    client = SimpleNamespace(run_pipeline=fail_safely)
    audit = Mock()
    monkeypatch.setattr(
        run_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(
        run_handlers,
        "_build_gitlab_write_client",
        Mock(return_value=client),
    )
    monkeypatch.setattr(run_handlers, "emit_action_audit", audit)
    update, message, _ = _callback_update(
        _OPERATOR_USER_ID,
        f"{run_handlers.RUN_PIPELINE_CALLBACK_PREFIX}{token}",
    )

    with caplog.at_level(logging.ERROR, logger="bot.run_pipeline_handlers"):
        asyncio.run(
            run_handlers.run_pipeline_confirmation_handler(
                update,
                object(),
            )
        )

    message.reply_text.assert_awaited_once_with(run_handlers.RUN_PIPELINE_UNAVAILABLE_MESSAGE)
    assert run_handlers.RUN_PIPELINE_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text
    assert _TOKEN not in caplog.text
    assert str(_OPERATOR_USER_ID) not in caplog.text
    assert audit.call_args_list[-1] == call(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        outcome=ActionAuditOutcome.FAILED,
        target=_target(),
    )

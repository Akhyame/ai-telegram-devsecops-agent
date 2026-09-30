"""Offline security tests for the predefined Telegram scan action."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest

import bot.handlers as base_handlers
import bot.scan_handlers as scan_handlers
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

_VIEWER_USER_ID = 101
_OPERATOR_USER_ID = 202
_SECOND_OPERATOR_USER_ID = 303
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
        status=PipelineStatus.CREATED,
        ref=_REF,
        sha=_FULL_SHA,
    )


def _configure_authorization(
    monkeypatch: pytest.MonkeyPatch,
    *,
    user_id: int,
    operator: bool,
) -> None:
    settings = SimpleNamespace(
        allowed_user_ids=frozenset({user_id}),
        operator_user_ids=(frozenset({user_id}) if operator else frozenset()),
        admin_user_ids=frozenset(),
    )
    monkeypatch.setattr(
        base_handlers,
        "get_bot_settings",
        lambda: settings,
    )


def _install_store(
    monkeypatch: pytest.MonkeyPatch,
) -> ActionConfirmationStore:
    store = ActionConfirmationStore(
        token_factory=lambda: _TOKEN,
    )
    monkeypatch.setattr(
        scan_handlers,
        "action_confirmation_store",
        store,
    )
    return store


def _request_update(
    user_id: int,
    *,
    args: tuple[str, ...] = (),
) -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    message = SimpleNamespace(reply_text=AsyncMock())
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=user_id),
        effective_message=message,
        callback_query=None,
    )
    context = SimpleNamespace(args=args)
    return update, message, context


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


def test_viewer_is_denied_before_write_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_VIEWER_USER_ID,
        operator=False,
    )
    get_settings = Mock()
    monkeypatch.setattr(
        scan_handlers,
        "get_gitlab_write_settings",
        get_settings,
    )
    update, message, context = _request_update(_VIEWER_USER_ID)

    asyncio.run(
        scan_handlers.scan_handler(
            update,
            context,
        )
    )

    message.reply_text.assert_awaited_once_with(base_handlers.ACCESS_DENIED_MESSAGE)
    get_settings.assert_not_called()


def test_scan_arguments_are_denied_without_gitlab_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_OPERATOR_USER_ID,
        operator=True,
    )
    store = _install_store(monkeypatch)
    audit = Mock()
    build_client = Mock()

    monkeypatch.setattr(
        scan_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(
        scan_handlers,
        "emit_action_audit",
        audit,
    )
    monkeypatch.setattr(
        scan_handlers,
        "_build_gitlab_write_client",
        build_client,
    )

    update, message, context = _request_update(
        _OPERATOR_USER_ID,
        args=("--config=untrusted",),
    )

    asyncio.run(
        scan_handlers.scan_handler(
            update,
            context,
        )
    )

    build_client.assert_not_called()
    assert store.pending_count == 0
    message.reply_text.assert_awaited_once_with(scan_handlers.SCAN_ARGUMENTS_NOT_ALLOWED_MESSAGE)
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.SCAN,
        outcome=ActionAuditOutcome.DENIED,
        target=_target(),
    )


def test_authorized_request_issues_confirmation_without_gitlab_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_OPERATOR_USER_ID,
        operator=True,
    )
    store = _install_store(monkeypatch)
    audit = Mock()
    build_client = Mock()

    monkeypatch.setattr(
        scan_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(
        scan_handlers,
        "emit_action_audit",
        audit,
    )
    monkeypatch.setattr(
        scan_handlers,
        "_build_gitlab_write_client",
        build_client,
    )

    update, message, context = _request_update(_OPERATOR_USER_ID)

    asyncio.run(
        scan_handlers.scan_handler(
            update,
            context,
        )
    )

    build_client.assert_not_called()
    assert store.pending_count == 1
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.SCAN,
        outcome=ActionAuditOutcome.REQUESTED,
        target=_target(),
    )

    reply = message.reply_text.await_args
    text = reply.args[0]
    button = reply.kwargs["reply_markup"].inline_keyboard[0][0]

    assert "predefined full GitLab security scan" in text
    assert _TOKEN not in text
    assert str(_PROJECT_ID) not in text
    assert button.text == scan_handlers.SCAN_CONFIRMATION_BUTTON
    assert button.callback_data == (f"{scan_handlers.SCAN_CALLBACK_PREFIX}{_TOKEN}")
    assert reply.kwargs["protect_content"] is True


def test_configuration_failure_is_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_OPERATOR_USER_ID,
        operator=True,
    )
    sensitive_detail = "DO-NOT-LEAK-SCAN-CONFIG"

    def fail_configuration() -> None:
        raise GitLabWriteConfigurationError(sensitive_detail)

    monkeypatch.setattr(
        scan_handlers,
        "get_gitlab_write_settings",
        fail_configuration,
    )

    update, message, context = _request_update(_OPERATOR_USER_ID)

    with caplog.at_level(
        logging.ERROR,
        logger="bot.scan_handlers",
    ):
        asyncio.run(
            scan_handlers.scan_handler(
                update,
                context,
            )
        )

    message.reply_text.assert_awaited_once_with(scan_handlers.SCAN_UNAVAILABLE_MESSAGE)
    assert scan_handlers.SCAN_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text


def test_matching_confirmation_launches_once_and_replay_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_OPERATOR_USER_ID,
        operator=True,
    )
    store = _install_store(monkeypatch)

    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.SCAN,
        target=_target(),
    )

    client = SimpleNamespace(run_security_scan=AsyncMock(return_value=_summary()))
    audit = Mock()

    monkeypatch.setattr(
        scan_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(
        scan_handlers,
        "_build_gitlab_write_client",
        Mock(return_value=client),
    )
    monkeypatch.setattr(
        scan_handlers,
        "emit_action_audit",
        audit,
    )

    callback_data = f"{scan_handlers.SCAN_CALLBACK_PREFIX}{token}"
    update, message, query = _callback_update(
        _OPERATOR_USER_ID,
        callback_data,
    )

    asyncio.run(
        scan_handlers.scan_confirmation_handler(
            update,
            object(),
        )
    )

    client.run_security_scan.assert_awaited_once_with()
    query.answer.assert_awaited_once_with()
    assert store.pending_count == 0

    success_text = message.reply_text.await_args.args[0]
    assert "GitLab security scan accepted." in success_text
    assert str(_PROJECT_ID) not in success_text
    assert _TOKEN not in success_text
    assert _FULL_SHA not in success_text
    assert _FULL_SHA[:8] in success_text

    replay_update, replay_message, replay_query = _callback_update(
        _OPERATOR_USER_ID,
        callback_data,
    )

    asyncio.run(
        scan_handlers.scan_confirmation_handler(
            replay_update,
            object(),
        )
    )

    client.run_security_scan.assert_awaited_once_with()
    replay_query.answer.assert_awaited_once_with()
    assert (
        replay_message.reply_text.await_args.args[0]
        == scan_handlers.SCAN_INVALID_CONFIRMATION_MESSAGE
    )

    assert audit.call_args_list == [
        call(
            user_id=_OPERATOR_USER_ID,
            action=ActionKind.SCAN,
            outcome=ActionAuditOutcome.CONFIRMED,
            target=_target(),
        ),
        call(
            user_id=_OPERATOR_USER_ID,
            action=ActionKind.SCAN,
            outcome=ActionAuditOutcome.SUCCEEDED,
            target=_target(),
        ),
        call(
            user_id=_OPERATOR_USER_ID,
            action=ActionKind.SCAN,
            outcome=ActionAuditOutcome.DENIED,
            target=_target(),
        ),
    ]


def test_confirmation_is_bound_to_original_operator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_SECOND_OPERATOR_USER_ID,
        operator=True,
    )
    store = _install_store(monkeypatch)

    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.SCAN,
        target=_target(),
    )

    build_client = Mock()
    audit = Mock()

    monkeypatch.setattr(
        scan_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(
        scan_handlers,
        "_build_gitlab_write_client",
        build_client,
    )
    monkeypatch.setattr(
        scan_handlers,
        "emit_action_audit",
        audit,
    )

    update, message, query = _callback_update(
        _SECOND_OPERATOR_USER_ID,
        f"{scan_handlers.SCAN_CALLBACK_PREFIX}{token}",
    )

    asyncio.run(
        scan_handlers.scan_confirmation_handler(
            update,
            object(),
        )
    )

    query.answer.assert_awaited_once_with()
    build_client.assert_not_called()
    assert store.pending_count == 1
    assert message.reply_text.await_args.args[0] == scan_handlers.SCAN_INVALID_CONFIRMATION_MESSAGE


def test_gitlab_failure_is_generic_and_audited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_OPERATOR_USER_ID,
        operator=True,
    )
    store = _install_store(monkeypatch)

    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.SCAN,
        target=_target(),
    )

    client = SimpleNamespace(
        run_security_scan=AsyncMock(side_effect=GitLabClientError(GitLabErrorKind.NETWORK))
    )
    audit = Mock()

    monkeypatch.setattr(
        scan_handlers,
        "get_gitlab_write_settings",
        _settings,
    )
    monkeypatch.setattr(
        scan_handlers,
        "_build_gitlab_write_client",
        Mock(return_value=client),
    )
    monkeypatch.setattr(
        scan_handlers,
        "emit_action_audit",
        audit,
    )

    update, message, _query = _callback_update(
        _OPERATOR_USER_ID,
        f"{scan_handlers.SCAN_CALLBACK_PREFIX}{token}",
    )

    asyncio.run(
        scan_handlers.scan_confirmation_handler(
            update,
            object(),
        )
    )

    client.run_security_scan.assert_awaited_once_with()
    message.reply_text.assert_awaited_once_with(scan_handlers.SCAN_UNAVAILABLE_MESSAGE)
    assert audit.call_args_list == [
        call(
            user_id=_OPERATOR_USER_ID,
            action=ActionKind.SCAN,
            outcome=ActionAuditOutcome.CONFIRMED,
            target=_target(),
        ),
        call(
            user_id=_OPERATOR_USER_ID,
            action=ActionKind.SCAN,
            outcome=ActionAuditOutcome.FAILED,
            target=_target(),
        ),
    ]

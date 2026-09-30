"""Offline security tests for confirmed cancel and retry actions."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest

import bot.handlers as base_handlers
import bot.pipeline_action_handlers as action_handlers
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
from bot.rbac import Role

_VIEWER_USER_ID = 101
_OPERATOR_USER_ID = 202
_ADMIN_USER_ID = 303
_SECOND_OPERATOR_USER_ID = 404

_API_URL = "https://gitlab.com/api/v4"
_PROJECT_ID = 123456
_PIPELINE_ID = 987654
_REF = "main"
_TOKEN = "A" * 32
_FULL_SHA = "abcdef0123456789abcdef0123456789abcdef01"


def _read_settings(
    *,
    ref: str = _REF,
) -> SimpleNamespace:
    return SimpleNamespace(
        api_url=_API_URL,
        project_id=_PROJECT_ID,
        default_ref=ref,
    )


def _write_settings(
    *,
    ref: str = _REF,
) -> SimpleNamespace:
    return SimpleNamespace(
        api_url=_API_URL,
        project_id=_PROJECT_ID,
        allowed_ref=ref,
    )


def _summary(
    status: PipelineStatus,
) -> PipelineSummary:
    return PipelineSummary(
        pipeline_id=_PIPELINE_ID,
        status=status,
        ref=_REF,
        sha=_FULL_SHA,
    )


def _result_summary(
    status: PipelineStatus,
) -> PipelineSummary:
    return PipelineSummary(
        pipeline_id=_PIPELINE_ID,
        status=status,
        ref=_REF,
        sha=_FULL_SHA,
    )


def _target() -> ActionTarget:
    return ActionTarget(
        project_id=_PROJECT_ID,
        ref=_REF,
        pipeline_id=_PIPELINE_ID,
    )


def _configure_authorization(
    monkeypatch: pytest.MonkeyPatch,
    *,
    user_id: int,
    role: Role,
) -> None:
    operator_ids = frozenset({user_id}) if role is Role.OPERATOR else frozenset()
    admin_ids = frozenset({user_id}) if role is Role.ADMIN else frozenset()

    settings = SimpleNamespace(
        allowed_user_ids=frozenset({user_id}),
        operator_user_ids=operator_ids,
        admin_user_ids=admin_ids,
    )

    monkeypatch.setattr(
        base_handlers,
        "get_bot_settings",
        lambda: settings,
    )


def _install_aligned_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        action_handlers,
        "get_gitlab_settings",
        _read_settings,
    )
    monkeypatch.setattr(
        action_handlers,
        "get_gitlab_write_settings",
        _write_settings,
    )


def _install_store(
    monkeypatch: pytest.MonkeyPatch,
) -> ActionConfirmationStore:
    store = ActionConfirmationStore(
        token_factory=lambda: _TOKEN,
    )
    monkeypatch.setattr(
        action_handlers,
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


@pytest.mark.parametrize(
    ("user_id", "role", "handler"),
    [
        (
            _VIEWER_USER_ID,
            Role.VIEWER,
            action_handlers.cancel_pipeline_handler,
        ),
        (
            _OPERATOR_USER_ID,
            Role.OPERATOR,
            action_handlers.cancel_pipeline_handler,
        ),
        (
            _VIEWER_USER_ID,
            Role.VIEWER,
            action_handlers.retry_pipeline_handler,
        ),
    ],
    ids=[
        "viewer-cancel-denied",
        "operator-cancel-denied",
        "viewer-retry-denied",
    ],
)
def test_unauthorized_roles_are_denied_before_gitlab_access(
    monkeypatch: pytest.MonkeyPatch,
    user_id: int,
    role: Role,
    handler: object,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=user_id,
        role=role,
    )
    get_read_settings = Mock()
    get_write_settings = Mock()
    monkeypatch.setattr(
        action_handlers,
        "get_gitlab_settings",
        get_read_settings,
    )
    monkeypatch.setattr(
        action_handlers,
        "get_gitlab_write_settings",
        get_write_settings,
    )
    update, message, context = _request_update(user_id)

    asyncio.run(handler(update, context))

    message.reply_text.assert_awaited_once_with(base_handlers.ACCESS_DENIED_MESSAGE)
    get_read_settings.assert_not_called()
    get_write_settings.assert_not_called()


@pytest.mark.parametrize(
    (
        "user_id",
        "role",
        "handler",
        "status",
        "action",
        "prefix",
        "button_text",
    ),
    [
        (
            _ADMIN_USER_ID,
            Role.ADMIN,
            action_handlers.cancel_pipeline_handler,
            PipelineStatus.RUNNING,
            ActionKind.CANCEL_PIPELINE,
            action_handlers.CANCEL_PIPELINE_CALLBACK_PREFIX,
            action_handlers.CANCEL_PIPELINE_CONFIRMATION_BUTTON,
        ),
        (
            _OPERATOR_USER_ID,
            Role.OPERATOR,
            action_handlers.retry_pipeline_handler,
            PipelineStatus.FAILED,
            ActionKind.RETRY_PIPELINE,
            action_handlers.RETRY_PIPELINE_CALLBACK_PREFIX,
            action_handlers.RETRY_PIPELINE_CONFIRMATION_BUTTON,
        ),
    ],
    ids=[
        "admin-cancel-request",
        "operator-retry-request",
    ],
)
def test_authorized_request_uses_server_selected_latest_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    user_id: int,
    role: Role,
    handler: object,
    status: PipelineStatus,
    action: ActionKind,
    prefix: str,
    button_text: str,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=user_id,
        role=role,
    )
    _install_aligned_settings(monkeypatch)
    store = _install_store(monkeypatch)

    read_client = SimpleNamespace(get_latest_pipeline=AsyncMock(return_value=_summary(status)))
    build_read_client = Mock(return_value=read_client)
    build_write_client = Mock()
    audit = Mock()

    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_read_client",
        build_read_client,
    )
    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_write_client",
        build_write_client,
    )
    monkeypatch.setattr(
        action_handlers,
        "emit_action_audit",
        audit,
    )

    update, message, context = _request_update(user_id)

    asyncio.run(handler(update, context))

    read_client.get_latest_pipeline.assert_awaited_once_with()
    build_write_client.assert_not_called()
    assert store.pending_count == 1

    audit.assert_called_once_with(
        user_id=user_id,
        action=action,
        outcome=ActionAuditOutcome.REQUESTED,
        target=_target(),
    )

    reply = message.reply_text.await_args
    text = reply.args[0]
    button = reply.kwargs["reply_markup"].inline_keyboard[0][0]

    assert str(_PROJECT_ID) not in text
    assert str(_PIPELINE_ID) not in text
    assert _TOKEN not in text
    assert f"Ref: {_REF}." in text
    assert f"Current status: {status.value}." in text

    assert button.text == button_text
    assert button.callback_data == (f"{prefix}{_PIPELINE_ID}:{_TOKEN}")
    assert len(button.callback_data.encode("ascii")) <= 64
    assert reply.kwargs["protect_content"] is True


def test_raw_pipeline_argument_is_rejected_and_never_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_ADMIN_USER_ID,
        role=Role.ADMIN,
    )
    _install_aligned_settings(monkeypatch)
    store = _install_store(monkeypatch)

    read_client = SimpleNamespace(
        get_latest_pipeline=AsyncMock(return_value=_summary(PipelineStatus.RUNNING))
    )
    build_write_client = Mock()
    audit = Mock()

    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_read_client",
        Mock(return_value=read_client),
    )
    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_write_client",
        build_write_client,
    )
    monkeypatch.setattr(
        action_handlers,
        "emit_action_audit",
        audit,
    )

    update, message, context = _request_update(
        _ADMIN_USER_ID,
        args=("999999999",),
    )

    asyncio.run(
        action_handlers.cancel_pipeline_handler(
            update,
            context,
        )
    )

    build_write_client.assert_not_called()
    assert store.pending_count == 0
    message.reply_text.assert_awaited_once_with(action_handlers.PIPELINE_ACTION_ARGUMENTS_MESSAGE)
    audit.assert_called_once_with(
        user_id=_ADMIN_USER_ID,
        action=ActionKind.CANCEL_PIPELINE,
        outcome=ActionAuditOutcome.DENIED,
        target=_target(),
    )


def test_ineligible_pipeline_state_is_denied_before_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_OPERATOR_USER_ID,
        role=Role.OPERATOR,
    )
    _install_aligned_settings(monkeypatch)
    store = _install_store(monkeypatch)

    read_client = SimpleNamespace(
        get_latest_pipeline=AsyncMock(return_value=_summary(PipelineStatus.SUCCESS))
    )
    build_write_client = Mock()
    audit = Mock()

    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_read_client",
        Mock(return_value=read_client),
    )
    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_write_client",
        build_write_client,
    )
    monkeypatch.setattr(
        action_handlers,
        "emit_action_audit",
        audit,
    )

    update, message, context = _request_update(_OPERATOR_USER_ID)

    asyncio.run(
        action_handlers.retry_pipeline_handler(
            update,
            context,
        )
    )

    build_write_client.assert_not_called()
    assert store.pending_count == 0
    message.reply_text.assert_awaited_once_with(action_handlers.PIPELINE_ACTION_NOT_ALLOWED_MESSAGE)
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RETRY_PIPELINE,
        outcome=ActionAuditOutcome.DENIED,
        target=_target(),
    )


@pytest.mark.parametrize(
    (
        "user_id",
        "role",
        "action",
        "prefix",
        "handler",
        "selected_method",
        "other_method",
        "result_status",
    ),
    [
        (
            _ADMIN_USER_ID,
            Role.ADMIN,
            ActionKind.CANCEL_PIPELINE,
            action_handlers.CANCEL_PIPELINE_CALLBACK_PREFIX,
            action_handlers.cancel_pipeline_confirmation_handler,
            "cancel_pipeline",
            "retry_pipeline",
            PipelineStatus.CANCELED,
        ),
        (
            _OPERATOR_USER_ID,
            Role.OPERATOR,
            ActionKind.RETRY_PIPELINE,
            action_handlers.RETRY_PIPELINE_CALLBACK_PREFIX,
            action_handlers.retry_pipeline_confirmation_handler,
            "retry_pipeline",
            "cancel_pipeline",
            PipelineStatus.PENDING,
        ),
    ],
    ids=[
        "cancel-once",
        "retry-once",
    ],
)
def test_matching_confirmation_executes_exactly_once_and_blocks_replay(
    monkeypatch: pytest.MonkeyPatch,
    user_id: int,
    role: Role,
    action: ActionKind,
    prefix: str,
    handler: object,
    selected_method: str,
    other_method: str,
    result_status: PipelineStatus,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=user_id,
        role=role,
    )
    _install_aligned_settings(monkeypatch)
    store = _install_store(monkeypatch)

    token = store.issue(
        user_id=user_id,
        action=action,
        target=_target(),
    )

    client = SimpleNamespace(
        cancel_pipeline=AsyncMock(return_value=_result_summary(result_status)),
        retry_pipeline=AsyncMock(return_value=_result_summary(result_status)),
    )
    build_write_client = Mock(return_value=client)
    audit = Mock()

    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_write_client",
        build_write_client,
    )
    monkeypatch.setattr(
        action_handlers,
        "emit_action_audit",
        audit,
    )

    callback_data = f"{prefix}{_PIPELINE_ID}:{token}"
    update, message, query = _callback_update(
        user_id,
        callback_data,
    )

    asyncio.run(handler(update, object()))

    selected = getattr(client, selected_method)
    other = getattr(client, other_method)

    selected.assert_awaited_once_with(_PIPELINE_ID)
    other.assert_not_awaited()
    query.answer.assert_awaited_once_with()
    assert store.pending_count == 0

    success_text = message.reply_text.await_args.args[0]
    assert str(_PROJECT_ID) not in success_text
    assert str(_PIPELINE_ID) not in success_text
    assert _TOKEN not in success_text
    assert _FULL_SHA not in success_text
    assert _FULL_SHA[:8] in success_text

    replay_update, replay_message, replay_query = _callback_update(
        user_id,
        callback_data,
    )

    asyncio.run(handler(replay_update, object()))

    selected.assert_awaited_once_with(_PIPELINE_ID)
    replay_query.answer.assert_awaited_once_with()
    assert (
        replay_message.reply_text.await_args.args[0]
        == action_handlers.PIPELINE_ACTION_INVALID_CONFIRMATION_MESSAGE
    )

    assert audit.call_args_list == [
        call(
            user_id=user_id,
            action=action,
            outcome=ActionAuditOutcome.CONFIRMED,
            target=_target(),
        ),
        call(
            user_id=user_id,
            action=action,
            outcome=ActionAuditOutcome.SUCCEEDED,
            target=_target(),
        ),
        call(
            user_id=user_id,
            action=action,
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
        role=Role.OPERATOR,
    )
    _install_aligned_settings(monkeypatch)
    store = _install_store(monkeypatch)

    token = store.issue(
        user_id=_OPERATOR_USER_ID,
        action=ActionKind.RETRY_PIPELINE,
        target=_target(),
    )

    build_write_client = Mock()
    audit = Mock()

    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_write_client",
        build_write_client,
    )
    monkeypatch.setattr(
        action_handlers,
        "emit_action_audit",
        audit,
    )

    update, message, query = _callback_update(
        _SECOND_OPERATOR_USER_ID,
        (f"{action_handlers.RETRY_PIPELINE_CALLBACK_PREFIX}{_PIPELINE_ID}:{token}"),
    )

    asyncio.run(
        action_handlers.retry_pipeline_confirmation_handler(
            update,
            object(),
        )
    )

    query.answer.assert_awaited_once_with()
    build_write_client.assert_not_called()
    assert store.pending_count == 1
    assert (
        message.reply_text.await_args.args[0]
        == action_handlers.PIPELINE_ACTION_INVALID_CONFIRMATION_MESSAGE
    )
    audit.assert_called_once_with(
        user_id=_SECOND_OPERATOR_USER_ID,
        action=ActionKind.RETRY_PIPELINE,
        outcome=ActionAuditOutcome.DENIED,
        target=_target(),
    )


def test_client_action_denial_is_generic_and_audited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_ADMIN_USER_ID,
        role=Role.ADMIN,
    )
    _install_aligned_settings(monkeypatch)
    store = _install_store(monkeypatch)

    token = store.issue(
        user_id=_ADMIN_USER_ID,
        action=ActionKind.CANCEL_PIPELINE,
        target=_target(),
    )

    client = SimpleNamespace(
        cancel_pipeline=AsyncMock(
            side_effect=GitLabClientError(GitLabErrorKind.ACTION_NOT_ALLOWED)
        ),
        retry_pipeline=AsyncMock(),
    )
    audit = Mock()

    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_write_client",
        Mock(return_value=client),
    )
    monkeypatch.setattr(
        action_handlers,
        "emit_action_audit",
        audit,
    )

    update, message, _query = _callback_update(
        _ADMIN_USER_ID,
        (f"{action_handlers.CANCEL_PIPELINE_CALLBACK_PREFIX}{_PIPELINE_ID}:{token}"),
    )

    asyncio.run(
        action_handlers.cancel_pipeline_confirmation_handler(
            update,
            object(),
        )
    )

    client.cancel_pipeline.assert_awaited_once_with(_PIPELINE_ID)
    message.reply_text.assert_awaited_once_with(action_handlers.PIPELINE_ACTION_NOT_ALLOWED_MESSAGE)
    assert audit.call_args_list == [
        call(
            user_id=_ADMIN_USER_ID,
            action=ActionKind.CANCEL_PIPELINE,
            outcome=ActionAuditOutcome.CONFIRMED,
            target=_target(),
        ),
        call(
            user_id=_ADMIN_USER_ID,
            action=ActionKind.CANCEL_PIPELINE,
            outcome=ActionAuditOutcome.DENIED,
            target=_target(),
        ),
    ]


def test_read_write_target_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(
        monkeypatch,
        user_id=_OPERATOR_USER_ID,
        role=Role.OPERATOR,
    )

    monkeypatch.setattr(
        action_handlers,
        "get_gitlab_settings",
        _read_settings,
    )
    monkeypatch.setattr(
        action_handlers,
        "get_gitlab_write_settings",
        lambda: _write_settings(ref="release"),
    )

    build_read_client = Mock()

    monkeypatch.setattr(
        action_handlers,
        "_build_gitlab_read_client",
        build_read_client,
    )

    update, message, context = _request_update(_OPERATOR_USER_ID)

    asyncio.run(
        action_handlers.retry_pipeline_handler(
            update,
            context,
        )
    )

    build_read_client.assert_not_called()
    message.reply_text.assert_awaited_once_with(action_handlers.PIPELINE_ACTION_UNAVAILABLE_MESSAGE)

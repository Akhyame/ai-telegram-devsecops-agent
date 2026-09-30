"""Offline tests for authorized Telegram command handlers."""

import asyncio
from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import bot.handlers as handlers
from bot.config import MAX_TELEGRAM_USER_ID, BotConfigurationError

_VIEWER_USER_ID = 101
_UNKNOWN_USER_ID = 404
_MISSING_USER = object()

Handler = Callable[[object, object], Awaitable[None]]


def _configure_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = SimpleNamespace(
        allowed_user_ids=frozenset({_VIEWER_USER_ID}),
        operator_user_ids=frozenset(),
        admin_user_ids=frozenset(),
    )
    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        lambda: settings,
    )


def _make_update(
    user_id: object,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    user = None if user_id is _MISSING_USER else SimpleNamespace(id=user_id)
    message = SimpleNamespace(reply_text=AsyncMock())
    update = SimpleNamespace(
        effective_user=user,
        effective_message=message,
    )

    return update, message


@pytest.mark.parametrize(
    ("handler", "expected_message"),
    [
        (handlers.start_handler, handlers.START_MESSAGE),
        (handlers.help_handler, handlers.HELP_MESSAGE),
    ],
    ids=[
        "start",
        "help",
    ],
)
def test_allowed_viewer_receives_non_mutating_command_response(
    monkeypatch: pytest.MonkeyPatch,
    handler: Handler,
    expected_message: str,
) -> None:
    _configure_authorization(monkeypatch)
    update, message = _make_update(_VIEWER_USER_ID)

    asyncio.run(handler(update, object()))

    message.reply_text.assert_awaited_once_with(expected_message)


def test_help_exposes_staging_only_deployment_command() -> None:
    assert "/deploy_staging" in handlers.HELP_MESSAGE
    assert "/deploy_production" not in handlers.HELP_MESSAGE
    assert "/deploy production" not in handlers.HELP_MESSAGE


@pytest.mark.parametrize(
    "handler",
    [
        handlers.start_handler,
        handlers.help_handler,
        handlers.status_handler,
    ],
    ids=[
        "start",
        "help",
        "status",
    ],
)
def test_unknown_user_receives_same_generic_denial(
    monkeypatch: pytest.MonkeyPatch,
    handler: Handler,
) -> None:
    _configure_authorization(monkeypatch)
    update, message = _make_update(_UNKNOWN_USER_ID)

    asyncio.run(handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.ACCESS_DENIED_MESSAGE)


@pytest.mark.parametrize(
    "invalid_user_id",
    [
        True,
        "101",
        101.0,
        MAX_TELEGRAM_USER_ID + 1,
    ],
    ids=[
        "boolean",
        "string",
        "float",
        "above-52-bit-limit",
    ],
)
def test_invalid_identity_receives_generic_denial(
    monkeypatch: pytest.MonkeyPatch,
    invalid_user_id: object,
) -> None:
    _configure_authorization(monkeypatch)
    update, message = _make_update(invalid_user_id)

    asyncio.run(handlers.start_handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.ACCESS_DENIED_MESSAGE)


def test_missing_user_receives_generic_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(monkeypatch)
    update, message = _make_update(_MISSING_USER)

    asyncio.run(handlers.start_handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.ACCESS_DENIED_MESSAGE)


def test_invalid_configuration_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_configuration_error() -> None:
        raise BotConfigurationError("Telegram bot configuration is invalid.")

    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        raise_configuration_error,
    )
    update, message = _make_update(_VIEWER_USER_ID)

    asyncio.run(handlers.start_handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.SERVICE_UNAVAILABLE_MESSAGE)


def test_update_without_effective_message_is_ignored_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    get_settings = Mock()
    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        get_settings,
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=_VIEWER_USER_ID),
        effective_message=None,
    )

    asyncio.run(handlers.start_handler(update, object()))

    get_settings.assert_not_called()

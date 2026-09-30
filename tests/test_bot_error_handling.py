"""Offline tests for safe Telegram fallback and error handling."""

import asyncio
import logging
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from telegram import Message, Update, User

from bot.config import get_bot_settings
from bot.error_handling import (
    ERROR_LOG_MESSAGE,
    UNKNOWN_COMMAND_MESSAGE,
    error_handler,
    unknown_command_handler,
)
from bot.handlers import ACCESS_DENIED_MESSAGE, SERVICE_UNAVAILABLE_MESSAGE

_ALLOWED_USER_ID = 101
_UNKNOWN_USER_ID = 202


def _valid_token() -> str:
    return str(123_456_789) + ":" + ("A" * 32)


def _update(
    user_id: object = _ALLOWED_USER_ID,
) -> tuple[Update, AsyncMock]:
    message = Mock(spec=Message)
    message.reply_text = AsyncMock()

    if user_id is None:
        message.from_user = None
    else:
        user = Mock(spec=User)
        user.id = user_id
        message.from_user = user

    return Update(update_id=1, message=message), message.reply_text


@pytest.fixture(autouse=True)
def _isolate_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_ALLOWED_USER_IDS", raising=False)
    monkeypatch.delenv("TELEGRAM_OPERATOR_USER_IDS", raising=False)
    monkeypatch.delenv("TELEGRAM_ADMIN_USER_IDS", raising=False)
    get_bot_settings.cache_clear()

    yield

    get_bot_settings.cache_clear()


def _configure_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())
    monkeypatch.setenv(
        "TELEGRAM_ALLOWED_USER_IDS",
        str(_ALLOWED_USER_ID),
    )


def test_allowlisted_identity_receives_unknown_command_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_allowlist(monkeypatch)
    update, reply_text = _update()

    asyncio.run(unknown_command_handler(update, Mock()))

    reply_text.assert_awaited_once_with(UNKNOWN_COMMAND_MESSAGE)


def test_unknown_identity_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_allowlist(monkeypatch)
    update, reply_text = _update(_UNKNOWN_USER_ID)

    asyncio.run(unknown_command_handler(update, Mock()))

    reply_text.assert_awaited_once_with(ACCESS_DENIED_MESSAGE)


def test_missing_identity_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_allowlist(monkeypatch)
    update, reply_text = _update(None)

    asyncio.run(unknown_command_handler(update, Mock()))

    reply_text.assert_awaited_once_with(ACCESS_DENIED_MESSAGE)


def test_configuration_failure_returns_generic_response() -> None:
    update, reply_text = _update()

    asyncio.run(unknown_command_handler(update, Mock()))

    reply_text.assert_awaited_once_with(SERVICE_UNAVAILABLE_MESSAGE)


def test_unknown_command_without_message_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_allowlist(monkeypatch)

    asyncio.run(
        unknown_command_handler(
            Update(update_id=1),
            Mock(),
        )
    )


def test_error_handler_logs_no_sensitive_details(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_detail = "DO-NOT-LOG-INTERNAL-DETAIL"
    update, reply_text = _update()
    context = SimpleNamespace(error=RuntimeError(sensitive_detail))

    with caplog.at_level(logging.ERROR, logger="bot.error_handling"):
        asyncio.run(error_handler(update, context))

    reply_text.assert_awaited_once_with(SERVICE_UNAVAILABLE_MESSAGE)
    assert ERROR_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text
    assert str(_ALLOWED_USER_ID) not in caplog.text


def test_error_handler_accepts_missing_update(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_detail = "DO-NOT-LOG-MISSING-UPDATE-DETAIL"
    context = SimpleNamespace(error=RuntimeError(sensitive_detail))

    with caplog.at_level(logging.ERROR, logger="bot.error_handling"):
        asyncio.run(error_handler(None, context))

    assert ERROR_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text

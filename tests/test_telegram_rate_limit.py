"""Tests for Telegram command/callback abuse throttling."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telegram.ext import ApplicationHandlerStop

from bot.telegram_rate_limit import (
    TELEGRAM_RATE_LIMIT_MAX_REQUESTS,
    telegram_rate_limit_handler,
    telegram_rate_limiter,
)


@pytest.fixture(autouse=True)
def _clear_rate_limiter():
    telegram_rate_limiter.clear()
    yield
    telegram_rate_limiter.clear()


def _command_update(user_id: int):
    return SimpleNamespace(
        callback_query=None,
        effective_user=SimpleNamespace(id=user_id),
        effective_message=SimpleNamespace(text="/status"),
    )


def _non_command_update(user_id: int):
    return SimpleNamespace(
        callback_query=None,
        effective_user=SimpleNamespace(id=user_id),
        effective_message=SimpleNamespace(text="hello"),
    )


def _callback_update(user_id: int):
    return SimpleNamespace(
        callback_query=SimpleNamespace(data="callback"),
        effective_user=SimpleNamespace(id=user_id),
        effective_message=None,
    )


def _run(update) -> None:
    asyncio.run(
        telegram_rate_limit_handler(
            update,
            AsyncMock(),
        )
    )


def test_telegram_rate_limit_allows_bounded_commands():
    update = _command_update(1001)

    for _ in range(TELEGRAM_RATE_LIMIT_MAX_REQUESTS):
        _run(update)


def test_telegram_rate_limit_blocks_excess_command():
    update = _command_update(1001)

    for _ in range(TELEGRAM_RATE_LIMIT_MAX_REQUESTS):
        _run(update)

    with pytest.raises(ApplicationHandlerStop):
        _run(update)


def test_telegram_rate_limit_is_per_user():
    first = _command_update(1001)
    second = _command_update(1002)

    for _ in range(TELEGRAM_RATE_LIMIT_MAX_REQUESTS):
        _run(first)

    with pytest.raises(ApplicationHandlerStop):
        _run(first)

    _run(second)


def test_telegram_rate_limit_covers_callbacks():
    update = _callback_update(1001)

    for _ in range(TELEGRAM_RATE_LIMIT_MAX_REQUESTS):
        _run(update)

    with pytest.raises(ApplicationHandlerStop):
        _run(update)


def test_telegram_rate_limit_ignores_non_control_messages():
    update = _non_command_update(1001)

    for _ in range(TELEGRAM_RATE_LIMIT_MAX_REQUESTS + 5):
        _run(update)


def test_telegram_rate_limit_fails_closed_without_valid_user():
    update = SimpleNamespace(
        callback_query=None,
        effective_user=None,
        effective_message=SimpleNamespace(text="/status"),
    )

    with pytest.raises(ApplicationHandlerStop):
        _run(update)

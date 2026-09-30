"""Offline tests for the Telegram application factory."""

from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    TypeHandler,
    filters,
)

from bot.application import build_application
from bot.config import BotConfigurationError, get_bot_settings
from bot.deploy_handlers import (
    DEPLOY_CALLBACK_PATTERN,
    deploy_confirmation_handler,
    deploy_handler,
    deploy_staging_handler,
)
from bot.error_handling import error_handler, unknown_command_handler
from bot.explain_handlers import (
    explain_handler,
    explain_security_handler,
)
from bot.handlers import help_handler, logs_handler, start_handler, status_handler
from bot.pipeline_action_handlers import (
    CANCEL_PIPELINE_CALLBACK_PATTERN,
    RETRY_PIPELINE_CALLBACK_PATTERN,
    cancel_pipeline_confirmation_handler,
    cancel_pipeline_handler,
    retry_pipeline_confirmation_handler,
    retry_pipeline_handler,
)
from bot.run_pipeline_handlers import (
    RUN_PIPELINE_CALLBACK_PATTERN,
    run_pipeline_confirmation_handler,
    run_pipeline_handler,
)
from bot.scan_handlers import (
    SCAN_CALLBACK_PATTERN,
    scan_confirmation_handler,
    scan_handler,
)
from bot.telegram_rate_limit import telegram_rate_limit_handler

_UNIMPLEMENTED_MUTATING_COMMANDS: frozenset[str] = frozenset()


def _valid_token() -> str:
    return str(123_456_789) + ":" + ("A" * 32)


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


def test_build_application_rejects_missing_configuration() -> None:
    with pytest.raises(
        BotConfigurationError,
        match=r"\ATelegram bot configuration is invalid\.\Z",
    ):
        build_application()


def test_build_application_registers_controlled_handlers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())

    application = build_application()

    assert set(application.handlers) == {-1, 0}

    security_handlers = application.handlers[-1]
    assert len(security_handlers) == 1
    assert isinstance(security_handlers[0], TypeHandler)
    assert security_handlers[0].callback is telegram_rate_limit_handler

    registered_handlers = application.handlers[0]
    assert len(registered_handlers) == 18

    command_handlers = [
        handler for handler in registered_handlers if isinstance(handler, CommandHandler)
    ]
    callbacks_by_command = {
        command: handler.callback for handler in command_handlers for command in handler.commands
    }

    assert callbacks_by_command == {
        "start": start_handler,
        "help": help_handler,
        "status": status_handler,
        "logs": logs_handler,
        "explain": explain_handler,
        "explain_security": explain_security_handler,
        "run_pipeline": run_pipeline_handler,
        "retry_pipeline": retry_pipeline_handler,
        "cancel_pipeline": cancel_pipeline_handler,
        "scan": scan_handler,
        "deploy": deploy_handler,
        "deploy_staging": deploy_staging_handler,
    }

    callback_handlers = [
        handler for handler in registered_handlers if isinstance(handler, CallbackQueryHandler)
    ]
    assert [
        (
            handler.callback,
            handler.pattern.pattern,
        )
        for handler in callback_handlers
    ] == [
        (
            run_pipeline_confirmation_handler,
            RUN_PIPELINE_CALLBACK_PATTERN,
        ),
        (
            retry_pipeline_confirmation_handler,
            RETRY_PIPELINE_CALLBACK_PATTERN,
        ),
        (
            cancel_pipeline_confirmation_handler,
            CANCEL_PIPELINE_CALLBACK_PATTERN,
        ),
        (
            scan_confirmation_handler,
            SCAN_CALLBACK_PATTERN,
        ),
        (
            deploy_confirmation_handler,
            DEPLOY_CALLBACK_PATTERN,
        ),
    ]

    message_handlers = [
        handler for handler in registered_handlers if isinstance(handler, MessageHandler)
    ]
    assert len(message_handlers) == 1
    assert message_handlers[0].callback is unknown_command_handler
    assert message_handlers[0].filters is filters.COMMAND
    assert application.error_handlers == {error_handler: True}


def test_build_application_registers_no_unimplemented_mutating_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())

    application = build_application()
    registered_commands = {
        command
        for handler in application.handlers[0]
        if isinstance(handler, CommandHandler)
        for command in handler.commands
    }

    assert registered_commands.isdisjoint(_UNIMPLEMENTED_MUTATING_COMMANDS)


def test_build_application_performs_no_network_or_runtime_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())

    with (
        patch(
            "telegram.request.HTTPXRequest.do_request",
            new_callable=AsyncMock,
        ) as request_call,
        patch.object(
            Application,
            "initialize",
            new_callable=AsyncMock,
        ) as initialize_call,
        patch.object(
            Application,
            "start",
            new_callable=AsyncMock,
        ) as start_call,
        patch.object(Application, "run_polling") as polling_call,
        patch.object(Application, "run_webhook") as webhook_call,
    ):
        application = build_application()

    assert application.running is False
    request_call.assert_not_awaited()
    initialize_call.assert_not_awaited()
    start_call.assert_not_awaited()
    polling_call.assert_not_called()
    webhook_call.assert_not_called()

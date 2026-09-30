"""Offline tests for the controlled Telegram runtime boundary."""

import logging
from unittest.mock import Mock

import pytest
from telegram.ext import Application

import bot.__main__ as bot_entrypoint
import bot.runtime as runtime
from bot.config import BotConfigurationError


def _application_mock() -> Mock:
    return Mock(spec=Application)


def test_main_runs_restricted_polling_offline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = _application_mock()
    build_application = Mock(return_value=application)
    monkeypatch.setattr(
        runtime,
        "build_application",
        build_application,
    )

    result = runtime.main()

    assert result == runtime.EXIT_SUCCESS
    build_application.assert_called_once_with()
    application.run_polling.assert_called_once_with(
        allowed_updates=("message", "callback_query"),
        bootstrap_retries=0,
        drop_pending_updates=True,
        close_loop=True,
        stop_signals=None,
    )


def test_configuration_failure_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_detail = "DO-NOT-LOG-CONFIGURATION-DETAIL"

    def raise_configuration_error() -> None:
        raise BotConfigurationError(sensitive_detail)

    monkeypatch.setattr(
        runtime,
        "build_application",
        raise_configuration_error,
    )

    with caplog.at_level(logging.ERROR, logger="bot.runtime"):
        result = runtime.main()

    assert result == runtime.EXIT_CONFIGURATION_FAILURE
    assert runtime.CONFIGURATION_FAILURE_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text


def test_runtime_failure_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_detail = "DO-NOT-LOG-RUNTIME-DETAIL"
    application = _application_mock()
    application.run_polling.side_effect = RuntimeError(sensitive_detail)
    monkeypatch.setattr(
        runtime,
        "build_application",
        Mock(return_value=application),
    )

    with caplog.at_level(logging.ERROR, logger="bot.runtime"):
        result = runtime.main()

    assert result == runtime.EXIT_RUNTIME_FAILURE
    assert runtime.RUNTIME_FAILURE_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text


def test_keyboard_interrupt_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = _application_mock()
    application.run_polling.side_effect = KeyboardInterrupt
    monkeypatch.setattr(
        runtime,
        "build_application",
        Mock(return_value=application),
    )

    with pytest.raises(KeyboardInterrupt):
        runtime.main()


def test_module_entrypoint_exposes_runtime_main() -> None:
    assert bot_entrypoint.main is runtime.main

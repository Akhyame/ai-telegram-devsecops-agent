"""Tests for the authorized Telegram /logs handler."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import bot.handlers as handlers
from bot.gitlab_client import PipelineStatus
from bot.gitlab_config import GitLabConfigurationError

VIEWER_ID = 101
OPERATOR_ID = 202
ADMIN_ID = 303


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        allowed_user_ids=(VIEWER_ID, OPERATOR_ID, ADMIN_ID),
        operator_user_ids=(OPERATOR_ID,),
        admin_user_ids=(ADMIN_ID,),
    )


def _update(
    user_id: int,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    message = SimpleNamespace(reply_text=AsyncMock())
    update = SimpleNamespace(
        effective_message=message,
        effective_user=SimpleNamespace(id=user_id),
    )
    return update, message


def _summary(
    *,
    truncated: bool,
) -> SimpleNamespace:
    return SimpleNamespace(
        job=SimpleNamespace(
            name="dependency-scan",
            status=PipelineStatus.FAILED,
        ),
        text=("line one\nhttps://example.invalid/build"),
        truncated=truncated,
    )


@pytest.mark.parametrize(
    "user_id",
    (OPERATOR_ID, ADMIN_ID),
)
def test_operator_and_admin_receive_sanitized_log(
    monkeypatch: pytest.MonkeyPatch,
    user_id: int,
) -> None:
    update, message = _update(user_id)
    summary = _summary(truncated=False)
    client = SimpleNamespace(get_latest_job_log=AsyncMock(return_value=summary))
    builder = Mock(return_value=client)

    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        _settings,
    )
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_log_client",
        builder,
    )

    asyncio.run(handlers.logs_handler(update, None))

    builder.assert_called_once_with()
    client.get_latest_job_log.assert_awaited_once_with()
    message.reply_text.assert_awaited_once_with(
        (
            "Latest GitLab job log: "
            "dependency-scan (failed).\n"
            "line one\n"
            "https://example.invalid/build"
        ),
        link_preview_options=(handlers.DISABLED_LOG_LINK_PREVIEW),
    )
    assert handlers.DISABLED_LOG_LINK_PREVIEW.is_disabled is True


def test_truncation_is_disclosed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update, message = _update(OPERATOR_ID)
    client = SimpleNamespace(get_latest_job_log=AsyncMock(return_value=_summary(truncated=True)))

    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        _settings,
    )
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_log_client",
        Mock(return_value=client),
    )

    asyncio.run(handlers.logs_handler(update, None))

    sent_text = message.reply_text.await_args.args[0]
    assert "dependency-scan (failed). Output truncated.\n" in sent_text


def test_viewer_is_denied_before_client_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update, message = _update(VIEWER_ID)
    builder = Mock()

    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        _settings,
    )
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_log_client",
        builder,
    )

    asyncio.run(handlers.logs_handler(update, None))

    message.reply_text.assert_awaited_once_with(handlers.ACCESS_DENIED_MESSAGE)
    builder.assert_not_called()


def test_missing_message_stops_before_client_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    update = SimpleNamespace(
        effective_message=None,
        effective_user=SimpleNamespace(id=OPERATOR_ID),
    )
    builder = Mock()

    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        _settings,
    )
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_log_client",
        builder,
    )

    asyncio.run(handlers.logs_handler(update, None))

    builder.assert_not_called()


def test_configuration_failure_is_generic_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    update, message = _update(OPERATOR_ID)
    sensitive_detail = "DO-NOT-LEAK-CONFIGURATION"
    builder = Mock(side_effect=GitLabConfigurationError(sensitive_detail))

    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        _settings,
    )
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_log_client",
        builder,
    )
    caplog.set_level(
        logging.ERROR,
        logger="bot.handlers",
    )

    asyncio.run(handlers.logs_handler(update, None))

    message.reply_text.assert_awaited_once_with(handlers.GITLAB_LOGS_UNAVAILABLE_MESSAGE)
    assert sensitive_detail not in caplog.text
    assert handlers.GITLAB_LOGS_LOG_MESSAGE in caplog.text

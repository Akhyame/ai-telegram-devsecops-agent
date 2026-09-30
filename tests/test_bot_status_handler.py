"""Offline tests for GitLab-backed Telegram status handling."""

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import bot.handlers as handlers
from bot.config import BotConfigurationError
from bot.gitlab_client import (
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_config import GitLabConfigurationError

_VIEWER_USER_ID = 101
_UNKNOWN_USER_ID = 404
_FULL_SHA = "abcdef0123456789abcdef0123456789abcdef01"


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
    message = SimpleNamespace(
        reply_text=AsyncMock(),
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=user_id),
        effective_message=message,
    )

    return update, message


def _pipeline_summary() -> PipelineSummary:
    return PipelineSummary(
        pipeline_id=987654,
        status=PipelineStatus.SUCCESS,
        ref="main",
        sha=_FULL_SHA,
    )


def test_allowed_viewer_receives_minimal_pipeline_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(monkeypatch)
    update, message = _make_update(_VIEWER_USER_ID)
    client = SimpleNamespace(get_latest_pipeline=AsyncMock(return_value=_pipeline_summary()))
    build_client = Mock(return_value=client)
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_client",
        build_client,
    )

    asyncio.run(handlers.status_handler(update, object()))

    message.reply_text.assert_awaited_once_with(
        "Bot status: operational. Latest GitLab pipeline: success. Ref: main. Commit: abcdef01."
    )
    build_client.assert_called_once_with()
    client.get_latest_pipeline.assert_awaited_once_with()

    reply = message.reply_text.await_args.args[0]
    assert _FULL_SHA not in reply
    assert "987654" not in reply


def test_authorization_precedes_gitlab_client_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(monkeypatch)
    update, message = _make_update(_UNKNOWN_USER_ID)
    build_client = Mock()
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_client",
        build_client,
    )

    asyncio.run(handlers.status_handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.ACCESS_DENIED_MESSAGE)
    build_client.assert_not_called()


def test_missing_message_prevents_gitlab_client_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_authorization(monkeypatch)
    build_client = Mock()
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_client",
        build_client,
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=_VIEWER_USER_ID),
        effective_message=None,
    )

    asyncio.run(handlers.status_handler(update, object()))

    build_client.assert_not_called()


def test_telegram_configuration_failure_precedes_gitlab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_detail = "DO-NOT-LEAK-TELEGRAM-CONFIG"

    def raise_configuration_error() -> None:
        raise BotConfigurationError(sensitive_detail)

    monkeypatch.setattr(
        handlers,
        "get_bot_settings",
        raise_configuration_error,
    )
    build_client = Mock()
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_client",
        build_client,
    )
    update, message = _make_update(_VIEWER_USER_ID)

    asyncio.run(handlers.status_handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.SERVICE_UNAVAILABLE_MESSAGE)
    build_client.assert_not_called()


def test_gitlab_configuration_failure_is_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _configure_authorization(monkeypatch)
    sensitive_detail = "DO-NOT-LEAK-GITLAB-CONFIG"
    update, message = _make_update(_VIEWER_USER_ID)

    def raise_configuration_error() -> None:
        raise GitLabConfigurationError(sensitive_detail)

    monkeypatch.setattr(
        handlers,
        "_build_gitlab_client",
        raise_configuration_error,
    )

    with caplog.at_level(
        logging.ERROR,
        logger="bot.handlers",
    ):
        asyncio.run(handlers.status_handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.GITLAB_STATUS_UNAVAILABLE_MESSAGE)
    assert handlers.GITLAB_STATUS_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text
    assert str(_VIEWER_USER_ID) not in caplog.text


def test_gitlab_client_failure_is_generic_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _configure_authorization(monkeypatch)
    sensitive_detail = "DO-NOT-LEAK-GITLAB-CLIENT"
    update, message = _make_update(_VIEWER_USER_ID)

    async def fail_safely() -> PipelineSummary:
        try:
            raise RuntimeError(sensitive_detail)
        except RuntimeError as exc:
            raise GitLabClientError(GitLabErrorKind.NETWORK) from exc

    client = SimpleNamespace(
        get_latest_pipeline=fail_safely,
    )
    monkeypatch.setattr(
        handlers,
        "_build_gitlab_client",
        lambda: client,
    )

    with caplog.at_level(
        logging.ERROR,
        logger="bot.handlers",
    ):
        asyncio.run(handlers.status_handler(update, object()))

    message.reply_text.assert_awaited_once_with(handlers.GITLAB_STATUS_UNAVAILABLE_MESSAGE)
    assert handlers.GITLAB_STATUS_LOG_MESSAGE in caplog.text
    assert sensitive_detail not in caplog.text
    assert str(_VIEWER_USER_ID) not in caplog.text

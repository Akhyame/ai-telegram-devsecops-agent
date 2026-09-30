"""Confirmed, audited, and allowlisted Telegram pipeline launch handlers."""

import logging

from telegram import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    LinkPreviewOptions,
    Update,
)
from telegram.ext import ContextTypes

import bot.handlers as base_handlers
from bot.action_audit import (
    ActionAuditError,
    ActionAuditOutcome,
    emit_action_audit,
)
from bot.action_confirmation import (
    ActionConfirmationError,
    ActionKind,
    ActionTarget,
    action_confirmation_store,
)
from bot.gitlab_client import GitLabClientError, PipelineSummary
from bot.gitlab_write_client import GitLabWriteClient
from bot.gitlab_write_config import (
    GitLabWriteConfigurationError,
    GitLabWriteSettings,
    get_gitlab_write_settings,
)
from bot.rbac import BotCommand

RUN_PIPELINE_CALLBACK_PREFIX = "run_pipeline:"
RUN_PIPELINE_CALLBACK_PATTERN = r"\Arun_pipeline:[A-Za-z0-9_-]{32}\Z"
RUN_PIPELINE_CONFIRMATION_BUTTON = "Confirm pipeline launch"
RUN_PIPELINE_INVALID_CONFIRMATION_MESSAGE = (
    "Confirmation is invalid or expired. Request /run_pipeline again."
)
RUN_PIPELINE_UNAVAILABLE_MESSAGE = "GitLab pipeline launch is unavailable."
RUN_PIPELINE_LOG_MESSAGE = "GitLab pipeline launch failed."
RUN_PIPELINE_AUDIT_LOG_MESSAGE = "Telegram pipeline action audit failed."
DISABLED_RUN_PIPELINE_LINK_PREVIEW = LinkPreviewOptions(is_disabled=True)

_LOGGER = logging.getLogger(__name__)


def _build_gitlab_write_client(
    settings: GitLabWriteSettings,
) -> GitLabWriteClient:
    """Build the isolated GitLab write client."""

    return GitLabWriteClient(settings)


def _target_from_settings(
    settings: GitLabWriteSettings,
) -> ActionTarget:
    """Build the exact server-controlled action target."""

    return ActionTarget(
        project_id=settings.project_id,
        ref=settings.allowed_ref,
    )


def _confirmation_message(
    ref: str,
) -> str:
    """Return a bounded confirmation prompt without internal identifiers."""

    return f"Confirm launching the allowed GitLab pipeline within 2 minutes. Ref: {ref}."


def _success_message(
    summary: PipelineSummary,
) -> str:
    """Return only validated and minimized pipeline fields."""

    return (
        "GitLab pipeline launch accepted. "
        f"Status: {summary.status.value}. "
        f"Ref: {summary.ref}. "
        f"Commit: {summary.sha[:8]}."
    )


def _emit_audit(
    *,
    user_id: int,
    outcome: ActionAuditOutcome,
    target: ActionTarget,
) -> bool:
    """Emit a controlled audit event and report deterministic failure."""

    try:
        emit_action_audit(
            user_id=user_id,
            action=ActionKind.RUN_PIPELINE,
            outcome=outcome,
            target=target,
        )
    except ActionAuditError:
        _LOGGER.error(RUN_PIPELINE_AUDIT_LOG_MESSAGE)
        return False

    return True


async def run_pipeline_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Create a fresh confirmation without contacting GitLab."""

    message = await base_handlers._authorized_message(
        update,
        BotCommand.RUN_PIPELINE,
    )

    if message is None:
        return

    user = update.effective_user
    if user is None:
        await message.reply_text(RUN_PIPELINE_UNAVAILABLE_MESSAGE)
        return

    try:
        settings = get_gitlab_write_settings()
        target = _target_from_settings(settings)
        token = action_confirmation_store.issue(
            user_id=user.id,
            action=ActionKind.RUN_PIPELINE,
            target=target,
        )
    except (
        GitLabWriteConfigurationError,
        ActionConfirmationError,
    ):
        _LOGGER.error(RUN_PIPELINE_LOG_MESSAGE)
        await message.reply_text(RUN_PIPELINE_UNAVAILABLE_MESSAGE)
        return

    if not _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.REQUESTED,
        target=target,
    ):
        await message.reply_text(RUN_PIPELINE_UNAVAILABLE_MESSAGE)
        return

    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    RUN_PIPELINE_CONFIRMATION_BUTTON,
                    callback_data=f"{RUN_PIPELINE_CALLBACK_PREFIX}{token}",
                )
            ]
        ]
    )

    await message.reply_text(
        _confirmation_message(settings.allowed_ref),
        reply_markup=keyboard,
        protect_content=True,
        link_preview_options=DISABLED_RUN_PIPELINE_LINK_PREVIEW,
    )


async def run_pipeline_confirmation_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Launch exactly one pipeline after a matching one-time confirmation."""

    query = update.callback_query
    if query is None:
        return

    await query.answer()

    message = await base_handlers._authorized_message(
        update,
        BotCommand.RUN_PIPELINE,
    )

    if message is None:
        return

    user = update.effective_user
    if user is None:
        await message.reply_text(RUN_PIPELINE_UNAVAILABLE_MESSAGE)
        return

    try:
        settings = get_gitlab_write_settings()
        target = _target_from_settings(settings)
    except (
        GitLabWriteConfigurationError,
        ActionConfirmationError,
    ):
        _LOGGER.error(RUN_PIPELINE_LOG_MESSAGE)
        await message.reply_text(RUN_PIPELINE_UNAVAILABLE_MESSAGE)
        return

    callback_data = query.data
    token = (
        callback_data.removeprefix(RUN_PIPELINE_CALLBACK_PREFIX)
        if isinstance(callback_data, str)
        else None
    )

    if not action_confirmation_store.claim(
        token,
        user_id=user.id,
        action=ActionKind.RUN_PIPELINE,
        target=target,
    ):
        _emit_audit(
            user_id=user.id,
            outcome=ActionAuditOutcome.DENIED,
            target=target,
        )
        await message.reply_text(
            RUN_PIPELINE_INVALID_CONFIRMATION_MESSAGE,
            protect_content=True,
            link_preview_options=DISABLED_RUN_PIPELINE_LINK_PREVIEW,
        )
        return

    if not _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.CONFIRMED,
        target=target,
    ):
        await message.reply_text(RUN_PIPELINE_UNAVAILABLE_MESSAGE)
        return

    try:
        client = _build_gitlab_write_client(settings)
        summary = await client.run_pipeline()
    except GitLabClientError:
        _emit_audit(
            user_id=user.id,
            outcome=ActionAuditOutcome.FAILED,
            target=target,
        )
        _LOGGER.error(RUN_PIPELINE_LOG_MESSAGE)
        await message.reply_text(RUN_PIPELINE_UNAVAILABLE_MESSAGE)
        return

    _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.SUCCEEDED,
        target=target,
    )

    await message.reply_text(
        _success_message(summary),
        protect_content=True,
        link_preview_options=DISABLED_RUN_PIPELINE_LINK_PREVIEW,
    )

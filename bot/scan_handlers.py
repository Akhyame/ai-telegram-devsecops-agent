"""Confirmed and audited Telegram handler for a predefined security scan."""

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
from bot.gitlab_client import (
    GitLabClientError,
    PipelineSummary,
)
from bot.gitlab_write_client import GitLabWriteClient
from bot.gitlab_write_config import (
    GitLabWriteConfigurationError,
    GitLabWriteSettings,
    get_gitlab_write_settings,
)
from bot.rbac import BotCommand

SCAN_CALLBACK_PREFIX = "scan:"
SCAN_CALLBACK_PATTERN = r"\Ascan:[A-Za-z0-9_-]{32}\Z"
SCAN_CONFIRMATION_BUTTON = "Confirm security scan"

SCAN_ARGUMENTS_NOT_ALLOWED_MESSAGE = (
    "The security scan profile is fixed. Arguments are not accepted."
)
SCAN_INVALID_CONFIRMATION_MESSAGE = "Confirmation is invalid or expired. Request /scan again."
SCAN_UNAVAILABLE_MESSAGE = "GitLab security scan is unavailable."
SCAN_LOG_MESSAGE = "GitLab security scan failed."
SCAN_AUDIT_LOG_MESSAGE = "Telegram security scan audit failed."

DISABLED_SCAN_LINK_PREVIEW = LinkPreviewOptions(is_disabled=True)

_LOGGER = logging.getLogger(__name__)


def _build_gitlab_write_client(
    settings: GitLabWriteSettings,
) -> GitLabWriteClient:
    """Build the isolated GitLab write client."""

    return GitLabWriteClient(settings)


def _target_from_settings(
    settings: GitLabWriteSettings,
) -> ActionTarget:
    """Build the fixed project-and-ref scan target."""

    return ActionTarget(
        project_id=settings.project_id,
        ref=settings.allowed_ref,
    )


def _emit_audit(
    *,
    user_id: int,
    outcome: ActionAuditOutcome,
    target: ActionTarget,
) -> bool:
    """Emit one controlled scan audit event."""

    try:
        emit_action_audit(
            user_id=user_id,
            action=ActionKind.SCAN,
            outcome=outcome,
            target=target,
        )
    except ActionAuditError:
        _LOGGER.error(SCAN_AUDIT_LOG_MESSAGE)
        return False

    return True


def _confirmation_message(
    ref: str,
) -> str:
    """Return a bounded prompt for the predefined full scan."""

    return (
        f"Confirm launching the predefined full GitLab security scan within 2 minutes. Ref: {ref}."
    )


def _success_message(
    summary: PipelineSummary,
) -> str:
    """Return only validated and minimized pipeline fields."""

    return (
        "GitLab security scan accepted. "
        f"Status: {summary.status.value}. "
        f"Ref: {summary.ref}. "
        f"Commit: {summary.sha[:8]}."
    )


async def scan_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Issue confirmation for one fixed full security scan."""

    message = await base_handlers._authorized_message(
        update,
        BotCommand.SCAN,
    )

    if message is None:
        return

    user = update.effective_user

    if user is None:
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    try:
        settings = get_gitlab_write_settings()
        target = _target_from_settings(settings)
    except (
        GitLabWriteConfigurationError,
        ActionConfirmationError,
    ):
        _LOGGER.error(SCAN_LOG_MESSAGE)
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    if getattr(context, "args", None):
        if not _emit_audit(
            user_id=user.id,
            outcome=ActionAuditOutcome.DENIED,
            target=target,
        ):
            await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
            return

        await message.reply_text(SCAN_ARGUMENTS_NOT_ALLOWED_MESSAGE)
        return

    try:
        token = action_confirmation_store.issue(
            user_id=user.id,
            action=ActionKind.SCAN,
            target=target,
        )
    except ActionConfirmationError:
        _LOGGER.error(SCAN_LOG_MESSAGE)
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    if not _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.REQUESTED,
        target=target,
    ):
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    SCAN_CONFIRMATION_BUTTON,
                    callback_data=(f"{SCAN_CALLBACK_PREFIX}{token}"),
                )
            ]
        ]
    )

    await message.reply_text(
        _confirmation_message(settings.allowed_ref),
        reply_markup=keyboard,
        protect_content=True,
        link_preview_options=DISABLED_SCAN_LINK_PREVIEW,
    )


async def scan_confirmation_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Launch one predefined scan after one-time confirmation."""

    query = update.callback_query

    if query is None:
        return

    await query.answer()

    message = await base_handlers._authorized_message(
        update,
        BotCommand.SCAN,
    )

    if message is None:
        return

    user = update.effective_user

    if user is None:
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    try:
        settings = get_gitlab_write_settings()
        target = _target_from_settings(settings)
    except (
        GitLabWriteConfigurationError,
        ActionConfirmationError,
    ):
        _LOGGER.error(SCAN_LOG_MESSAGE)
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    callback_data = query.data
    token = (
        callback_data.removeprefix(SCAN_CALLBACK_PREFIX) if isinstance(callback_data, str) else None
    )

    if not action_confirmation_store.claim(
        token,
        user_id=user.id,
        action=ActionKind.SCAN,
        target=target,
    ):
        _emit_audit(
            user_id=user.id,
            outcome=ActionAuditOutcome.DENIED,
            target=target,
        )
        await message.reply_text(
            SCAN_INVALID_CONFIRMATION_MESSAGE,
            protect_content=True,
            link_preview_options=DISABLED_SCAN_LINK_PREVIEW,
        )
        return

    if not _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.CONFIRMED,
        target=target,
    ):
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    try:
        client = _build_gitlab_write_client(settings)
        summary = await client.run_security_scan()
    except GitLabClientError:
        _emit_audit(
            user_id=user.id,
            outcome=ActionAuditOutcome.FAILED,
            target=target,
        )
        _LOGGER.error(SCAN_LOG_MESSAGE)
        await message.reply_text(SCAN_UNAVAILABLE_MESSAGE)
        return

    _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.SUCCEEDED,
        target=target,
    )

    await message.reply_text(
        _success_message(summary),
        protect_content=True,
        link_preview_options=DISABLED_SCAN_LINK_PREVIEW,
    )

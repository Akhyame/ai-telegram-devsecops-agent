"""Confirmed, audited, and server-selected pipeline action handlers."""

import logging
import re
from dataclasses import dataclass

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
    GitLabClient,
    GitLabClientError,
    GitLabErrorKind,
    PipelineStatus,
    PipelineSummary,
)
from bot.gitlab_config import (
    GitLabConfigurationError,
    GitLabSettings,
    get_gitlab_settings,
)
from bot.gitlab_write_client import GitLabWriteClient
from bot.gitlab_write_config import (
    GitLabWriteConfigurationError,
    GitLabWriteSettings,
    get_gitlab_write_settings,
)
from bot.rbac import BotCommand

CANCEL_PIPELINE_CALLBACK_PREFIX = "pc:"
RETRY_PIPELINE_CALLBACK_PREFIX = "pr:"

CANCEL_PIPELINE_CALLBACK_PATTERN = r"\Apc:[1-9][0-9]{0,18}:[A-Za-z0-9_-]{32}\Z"
RETRY_PIPELINE_CALLBACK_PATTERN = r"\Apr:[1-9][0-9]{0,18}:[A-Za-z0-9_-]{32}\Z"

CANCEL_PIPELINE_CONFIRMATION_BUTTON = "Confirm pipeline cancellation"
RETRY_PIPELINE_CONFIRMATION_BUTTON = "Confirm pipeline retry"

PIPELINE_ACTION_ARGUMENTS_MESSAGE = "This command does not accept arguments."
PIPELINE_ACTION_INVALID_CONFIRMATION_MESSAGE = (
    "Confirmation is invalid or expired. Request the command again."
)
PIPELINE_ACTION_NOT_ALLOWED_MESSAGE = "No eligible GitLab pipeline is available for this action."
PIPELINE_ACTION_UNAVAILABLE_MESSAGE = "GitLab pipeline action is unavailable."
PIPELINE_ACTION_LOG_MESSAGE = "GitLab pipeline action failed."
PIPELINE_ACTION_AUDIT_LOG_MESSAGE = "Telegram pipeline action audit failed."

DISABLED_PIPELINE_ACTION_LINK_PREVIEW = LinkPreviewOptions(is_disabled=True)

_MAX_IDENTIFIER = (2**63) - 1

_CANCEL_ALLOWED_STATUSES = frozenset(
    {
        PipelineStatus.CREATED,
        PipelineStatus.WAITING_FOR_RESOURCE,
        PipelineStatus.PREPARING,
        PipelineStatus.WAITING_FOR_CALLBACK,
        PipelineStatus.PENDING,
        PipelineStatus.RUNNING,
        PipelineStatus.MANUAL,
        PipelineStatus.SCHEDULED,
    }
)

_RETRY_ALLOWED_STATUSES = frozenset(
    {
        PipelineStatus.FAILED,
        PipelineStatus.CANCELED,
    }
)

_LOGGER = logging.getLogger(__name__)


class PipelineActionHandlerError(RuntimeError):
    """Static failure for invalid pipeline action state."""


@dataclass(frozen=True, slots=True)
class _PipelineActionSpec:
    command: BotCommand
    action: ActionKind
    callback_prefix: str
    callback_pattern: str
    button_text: str
    prompt_verb: str
    success_label: str
    allowed_statuses: frozenset[PipelineStatus]


_CANCEL_SPEC = _PipelineActionSpec(
    command=BotCommand.CANCEL_PIPELINE,
    action=ActionKind.CANCEL_PIPELINE,
    callback_prefix=CANCEL_PIPELINE_CALLBACK_PREFIX,
    callback_pattern=CANCEL_PIPELINE_CALLBACK_PATTERN,
    button_text=CANCEL_PIPELINE_CONFIRMATION_BUTTON,
    prompt_verb="canceling",
    success_label="cancellation",
    allowed_statuses=_CANCEL_ALLOWED_STATUSES,
)

_RETRY_SPEC = _PipelineActionSpec(
    command=BotCommand.RETRY_PIPELINE,
    action=ActionKind.RETRY_PIPELINE,
    callback_prefix=RETRY_PIPELINE_CALLBACK_PREFIX,
    callback_pattern=RETRY_PIPELINE_CALLBACK_PATTERN,
    button_text=RETRY_PIPELINE_CONFIRMATION_BUTTON,
    prompt_verb="retrying",
    success_label="retry",
    allowed_statuses=_RETRY_ALLOWED_STATUSES,
)


def _build_gitlab_read_client(
    settings: GitLabSettings,
) -> GitLabClient:
    """Build the isolated read-only GitLab client."""

    return GitLabClient(settings)


def _build_gitlab_write_client(
    settings: GitLabWriteSettings,
) -> GitLabWriteClient:
    """Build the isolated GitLab write client."""

    return GitLabWriteClient(settings)


def _load_aligned_settings() -> tuple[GitLabSettings, GitLabWriteSettings]:
    """Load read/write settings and require one identical target boundary."""

    read_settings = get_gitlab_settings()
    write_settings = get_gitlab_write_settings()

    if (
        read_settings.api_url != write_settings.api_url
        or read_settings.project_id != write_settings.project_id
        or read_settings.default_ref != write_settings.allowed_ref
    ):
        raise PipelineActionHandlerError("GitLab read/write targets are inconsistent.")

    return read_settings, write_settings


async def _resolve_latest_pipeline(
    read_settings: GitLabSettings,
) -> PipelineSummary:
    """Resolve the latest pipeline through the read-only credential."""

    client = _build_gitlab_read_client(read_settings)
    return await client.get_latest_pipeline()


def _target_from_summary(
    settings: GitLabWriteSettings,
    summary: PipelineSummary,
) -> ActionTarget:
    """Build the exact server-selected action target."""

    if summary.ref != settings.allowed_ref:
        raise PipelineActionHandlerError("GitLab pipeline target is inconsistent.")

    return ActionTarget(
        project_id=settings.project_id,
        ref=settings.allowed_ref,
        pipeline_id=summary.pipeline_id,
    )


def _emit_audit(
    *,
    user_id: int,
    spec: _PipelineActionSpec,
    outcome: ActionAuditOutcome,
    target: ActionTarget,
) -> bool:
    """Emit a controlled action event and fail deterministically."""

    try:
        emit_action_audit(
            user_id=user_id,
            action=spec.action,
            outcome=outcome,
            target=target,
        )
    except ActionAuditError:
        _LOGGER.error(PIPELINE_ACTION_AUDIT_LOG_MESSAGE)
        return False

    return True


def _confirmation_message(
    spec: _PipelineActionSpec,
    summary: PipelineSummary,
) -> str:
    """Return a minimized confirmation prompt."""

    return (
        f"Confirm {spec.prompt_verb} the latest allowed GitLab pipeline "
        "within 2 minutes. "
        f"Ref: {summary.ref}. "
        f"Current status: {summary.status.value}."
    )


def _success_message(
    spec: _PipelineActionSpec,
    summary: PipelineSummary,
) -> str:
    """Return only validated and minimized pipeline fields."""

    return (
        f"GitLab pipeline {spec.success_label} accepted. "
        f"Status: {summary.status.value}. "
        f"Ref: {summary.ref}. "
        f"Commit: {summary.sha[:8]}."
    )


def _callback_data(
    spec: _PipelineActionSpec,
    target: ActionTarget,
    token: str,
) -> str:
    """Build bounded callback data from server-controlled values."""

    pipeline_id = target.pipeline_id

    if pipeline_id is None:
        raise PipelineActionHandlerError("Pipeline action target is incomplete.")

    value = f"{spec.callback_prefix}{pipeline_id}:{token}"

    if len(value.encode("ascii")) > 64:
        raise PipelineActionHandlerError("Pipeline action callback is too large.")

    return value


def _parse_callback(
    value: object,
    spec: _PipelineActionSpec,
) -> tuple[int, str] | None:
    """Parse one strictly bounded callback payload."""

    if not isinstance(value, str) or re.fullmatch(spec.callback_pattern, value) is None:
        return None

    remainder = value.removeprefix(spec.callback_prefix)
    pipeline_text, token = remainder.split(":", maxsplit=1)
    pipeline_id = int(pipeline_text)

    if pipeline_id > _MAX_IDENTIFIER:
        return None

    return pipeline_id, token


async def _request_pipeline_action(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    spec: _PipelineActionSpec,
) -> None:
    """Resolve a server-selected target and issue a fresh confirmation."""

    message = await base_handlers._authorized_message(
        update,
        spec.command,
    )

    if message is None:
        return

    user = update.effective_user

    if user is None:
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    try:
        read_settings, write_settings = _load_aligned_settings()
        summary = await _resolve_latest_pipeline(read_settings)
        target = _target_from_summary(write_settings, summary)
    except (
        GitLabConfigurationError,
        GitLabWriteConfigurationError,
        GitLabClientError,
        PipelineActionHandlerError,
        ActionConfirmationError,
    ):
        _LOGGER.error(PIPELINE_ACTION_LOG_MESSAGE)
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    if getattr(context, "args", None):
        if not _emit_audit(
            user_id=user.id,
            spec=spec,
            outcome=ActionAuditOutcome.DENIED,
            target=target,
        ):
            await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
            return

        await message.reply_text(PIPELINE_ACTION_ARGUMENTS_MESSAGE)
        return

    if summary.status not in spec.allowed_statuses:
        if not _emit_audit(
            user_id=user.id,
            spec=spec,
            outcome=ActionAuditOutcome.DENIED,
            target=target,
        ):
            await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
            return

        await message.reply_text(PIPELINE_ACTION_NOT_ALLOWED_MESSAGE)
        return

    try:
        token = action_confirmation_store.issue(
            user_id=user.id,
            action=spec.action,
            target=target,
        )
        callback_data = _callback_data(
            spec,
            target,
            token,
        )
    except (
        ActionConfirmationError,
        PipelineActionHandlerError,
    ):
        _LOGGER.error(PIPELINE_ACTION_LOG_MESSAGE)
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    if not _emit_audit(
        user_id=user.id,
        spec=spec,
        outcome=ActionAuditOutcome.REQUESTED,
        target=target,
    ):
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    spec.button_text,
                    callback_data=callback_data,
                )
            ]
        ]
    )

    await message.reply_text(
        _confirmation_message(spec, summary),
        reply_markup=keyboard,
        protect_content=True,
        link_preview_options=DISABLED_PIPELINE_ACTION_LINK_PREVIEW,
    )


async def _execute_pipeline_action(
    client: GitLabWriteClient,
    spec: _PipelineActionSpec,
    pipeline_id: int,
) -> PipelineSummary:
    """Execute one allowlisted client method."""

    if spec.action is ActionKind.CANCEL_PIPELINE:
        return await client.cancel_pipeline(pipeline_id)

    if spec.action is ActionKind.RETRY_PIPELINE:
        return await client.retry_pipeline(pipeline_id)

    raise PipelineActionHandlerError("Pipeline action is not supported.")


async def _confirm_pipeline_action(
    update: Update,
    spec: _PipelineActionSpec,
) -> None:
    """Claim one confirmation and execute its bound action exactly once."""

    query = update.callback_query

    if query is None:
        return

    await query.answer()

    message = await base_handlers._authorized_message(
        update,
        spec.command,
    )

    if message is None:
        return

    user = update.effective_user

    if user is None:
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    parsed = _parse_callback(
        query.data,
        spec,
    )

    if parsed is None:
        await message.reply_text(
            PIPELINE_ACTION_INVALID_CONFIRMATION_MESSAGE,
            protect_content=True,
            link_preview_options=DISABLED_PIPELINE_ACTION_LINK_PREVIEW,
        )
        return

    pipeline_id, token = parsed

    try:
        _read_settings, write_settings = _load_aligned_settings()
        target = ActionTarget(
            project_id=write_settings.project_id,
            ref=write_settings.allowed_ref,
            pipeline_id=pipeline_id,
        )
        claimed = action_confirmation_store.claim(
            token,
            user_id=user.id,
            action=spec.action,
            target=target,
        )
    except (
        GitLabConfigurationError,
        GitLabWriteConfigurationError,
        PipelineActionHandlerError,
        ActionConfirmationError,
    ):
        _LOGGER.error(PIPELINE_ACTION_LOG_MESSAGE)
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    if not claimed:
        _emit_audit(
            user_id=user.id,
            spec=spec,
            outcome=ActionAuditOutcome.DENIED,
            target=target,
        )
        await message.reply_text(
            PIPELINE_ACTION_INVALID_CONFIRMATION_MESSAGE,
            protect_content=True,
            link_preview_options=DISABLED_PIPELINE_ACTION_LINK_PREVIEW,
        )
        return

    if not _emit_audit(
        user_id=user.id,
        spec=spec,
        outcome=ActionAuditOutcome.CONFIRMED,
        target=target,
    ):
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    try:
        client = _build_gitlab_write_client(write_settings)
        summary = await _execute_pipeline_action(
            client,
            spec,
            pipeline_id,
        )
    except GitLabClientError as exc:
        outcome = (
            ActionAuditOutcome.DENIED
            if exc.kind is GitLabErrorKind.ACTION_NOT_ALLOWED
            else ActionAuditOutcome.FAILED
        )
        _emit_audit(
            user_id=user.id,
            spec=spec,
            outcome=outcome,
            target=target,
        )
        _LOGGER.error(PIPELINE_ACTION_LOG_MESSAGE)

        message_text = (
            PIPELINE_ACTION_NOT_ALLOWED_MESSAGE
            if exc.kind is GitLabErrorKind.ACTION_NOT_ALLOWED
            else PIPELINE_ACTION_UNAVAILABLE_MESSAGE
        )
        await message.reply_text(message_text)
        return
    except PipelineActionHandlerError:
        _emit_audit(
            user_id=user.id,
            spec=spec,
            outcome=ActionAuditOutcome.FAILED,
            target=target,
        )
        _LOGGER.error(PIPELINE_ACTION_LOG_MESSAGE)
        await message.reply_text(PIPELINE_ACTION_UNAVAILABLE_MESSAGE)
        return

    _emit_audit(
        user_id=user.id,
        spec=spec,
        outcome=ActionAuditOutcome.SUCCEEDED,
        target=target,
    )

    await message.reply_text(
        _success_message(spec, summary),
        protect_content=True,
        link_preview_options=DISABLED_PIPELINE_ACTION_LINK_PREVIEW,
    )


async def cancel_pipeline_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Request confirmation for the latest cancelable pipeline."""

    await _request_pipeline_action(
        update,
        context,
        _CANCEL_SPEC,
    )


async def retry_pipeline_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Request confirmation for the latest retryable pipeline."""

    await _request_pipeline_action(
        update,
        context,
        _RETRY_SPEC,
    )


async def cancel_pipeline_confirmation_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Confirm one server-selected pipeline cancellation."""

    await _confirm_pipeline_action(
        update,
        _CANCEL_SPEC,
    )


async def retry_pipeline_confirmation_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Confirm one server-selected pipeline retry."""

    await _confirm_pipeline_action(
        update,
        _RETRY_SPEC,
    )

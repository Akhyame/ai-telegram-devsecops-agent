"""Authorized non-mutating Telegram command handlers."""

import logging

from telegram import (
    LinkPreviewOptions,
    Message,
    Update,
)
from telegram.ext import ContextTypes

from bot.config import (
    BotConfigurationError,
    get_bot_settings,
)
from bot.gitlab_client import (
    GitLabClient,
    GitLabClientError,
    PipelineSummary,
)
from bot.gitlab_config import (
    GitLabConfigurationError,
    get_gitlab_settings,
)
from bot.gitlab_logs import (
    GitLabJobLogClient,
    JobLogSummary,
)
from bot.rbac import (
    BotCommand,
    is_user_command_allowed,
)

ACCESS_DENIED_MESSAGE = "Access denied."
SERVICE_UNAVAILABLE_MESSAGE = "Service unavailable."
START_MESSAGE = "Secure DevSecOps control bot. Use /help to view available commands."
HELP_MESSAGE = (
    "AI DevSecOps Agent - Commands\n\n"
    "Viewer\n"
    "/start - Start the bot.\n"
    "/help - Show this command guide.\n"
    "/status - Show the latest GitLab pipeline status.\n\n"
    "Operator / Admin\n"
    "/logs - Show sanitized logs from the latest GitLab job.\n"
    "/explain - Explain the latest pipeline failure using bounded evidence.\n"
    "/explain_security - Explain the latest deterministic Security Gate result.\n"
    "/run_pipeline - Launch the approved full CI/CD pipeline.\n"
    "/retry_pipeline - Retry an eligible failed pipeline.\n"
    "/scan - Launch the approved security-only pipeline.\n\n"
    "Admin\n"
    "/cancel_pipeline - Cancel an eligible running pipeline.\n"
    "/deploy_staging - Deploy the validated application to staging.\n\n"
    "Sensitive actions remain authorization- and confirmation-bound."
)
STATUS_MESSAGE_PREFIX = "Bot status: operational."
GITLAB_STATUS_UNAVAILABLE_MESSAGE = (
    "Bot status: operational. GitLab pipeline status is unavailable."
)
GITLAB_STATUS_LOG_MESSAGE = "GitLab pipeline status retrieval failed."
GITLAB_LOGS_UNAVAILABLE_MESSAGE = "GitLab job logs are unavailable."
GITLAB_LOGS_LOG_MESSAGE = "GitLab job log retrieval failed."
LOGS_MESSAGE_PREFIX = "Latest GitLab job log:"
LOGS_TRUNCATED_MESSAGE = " Output truncated."
DISABLED_LOG_LINK_PREVIEW = LinkPreviewOptions(is_disabled=True)

_LOGGER = logging.getLogger(__name__)


async def _authorized_message(
    update: Update,
    command: BotCommand,
) -> Message | None:
    """Return the effective message only after deterministic authorization."""

    message = update.effective_message

    if message is None:
        return None

    user = update.effective_user
    user_id = None if user is None else user.id

    try:
        settings = get_bot_settings()
    except BotConfigurationError:
        await message.reply_text(SERVICE_UNAVAILABLE_MESSAGE)
        return None

    if not is_user_command_allowed(
        user_id,
        command,
        allowed_user_ids=(settings.allowed_user_ids),
        operator_user_ids=(settings.operator_user_ids),
        admin_user_ids=(settings.admin_user_ids),
    ):
        await message.reply_text(ACCESS_DENIED_MESSAGE)
        return None

    return message


def _build_gitlab_client() -> GitLabClient:
    """Build the validated read-only GitLab client."""

    return GitLabClient(get_gitlab_settings())


def _build_gitlab_log_client() -> GitLabJobLogClient:
    """Build the bounded read-only GitLab log client."""

    return GitLabJobLogClient(get_gitlab_settings())


def _pipeline_status_message(
    summary: PipelineSummary,
) -> str:
    """Format only validated, non-sensitive pipeline fields."""

    short_sha = summary.sha[:8]

    return (
        f"{STATUS_MESSAGE_PREFIX} "
        "Latest GitLab pipeline: "
        f"{summary.status.value}. "
        f"Ref: {summary.ref}. "
        f"Commit: {short_sha}."
    )


def _job_log_message(
    summary: JobLogSummary,
) -> str:
    """Format a validated job header and sanitized bounded trace."""

    truncated = LOGS_TRUNCATED_MESSAGE if summary.truncated else ""

    return (
        f"{LOGS_MESSAGE_PREFIX} "
        f"{summary.job.name} "
        f"({summary.job.status.value})."
        f"{truncated}\n"
        f"{summary.text}"
    )


async def start_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Handle /start after authorization."""

    message = await _authorized_message(
        update,
        BotCommand.START,
    )

    if message is not None:
        await message.reply_text(START_MESSAGE)


async def help_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Handle /help after authorization."""

    message = await _authorized_message(
        update,
        BotCommand.HELP,
    )

    if message is not None:
        await message.reply_text(HELP_MESSAGE)


async def status_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Return a validated GitLab pipeline summary after authorization."""

    message = await _authorized_message(
        update,
        BotCommand.STATUS,
    )

    if message is None:
        return

    try:
        client = _build_gitlab_client()
        summary = await client.get_latest_pipeline()
    except (
        GitLabConfigurationError,
        GitLabClientError,
    ):
        _LOGGER.error(GITLAB_STATUS_LOG_MESSAGE)
        await message.reply_text(GITLAB_STATUS_UNAVAILABLE_MESSAGE)
        return

    await message.reply_text(_pipeline_status_message(summary))


async def logs_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Return one sanitized bounded job log after Operator authorization."""

    message = await _authorized_message(
        update,
        BotCommand.LOGS,
    )

    if message is None:
        return

    try:
        client = _build_gitlab_log_client()
        summary = await client.get_latest_job_log()
    except (
        GitLabConfigurationError,
        GitLabClientError,
    ):
        _LOGGER.error(GITLAB_LOGS_LOG_MESSAGE)
        await message.reply_text(GITLAB_LOGS_UNAVAILABLE_MESSAGE)
        return

    await message.reply_text(
        _job_log_message(summary),
        link_preview_options=(DISABLED_LOG_LINK_PREVIEW),
    )

"""Admin-only, confirmed, and audited Telegram deployment handlers."""

import logging
import re

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
from deployment.models import DeploymentEnvironment

DEPLOY_CALLBACK_PREFIX = "deploy:"
DEPLOY_CALLBACK_PATTERN = (
    r"\Adeploy:(?P<environment>staging):"
    r"(?P<token>[A-Za-z0-9_-]{32})\Z"
)
DEPLOY_CONFIRMATION_BUTTON = "Confirm deployment"
DEPLOY_USAGE_MESSAGE = "Usage: /deploy staging."
DEPLOY_INVALID_CONFIRMATION_MESSAGE = "Confirmation is invalid or expired. Request /deploy again."
DEPLOY_UNAVAILABLE_MESSAGE = "GitLab deployment is unavailable."
DEPLOY_LOG_MESSAGE = "GitLab deployment launch failed."
DEPLOY_AUDIT_LOG_MESSAGE = "Telegram deployment audit failed."
DISABLED_DEPLOY_LINK_PREVIEW = LinkPreviewOptions(is_disabled=True)

_LOGGER = logging.getLogger(__name__)


def _build_gitlab_write_client(
    settings: GitLabWriteSettings,
) -> GitLabWriteClient:
    """Build the isolated GitLab write client."""

    return GitLabWriteClient(settings)


def _parse_environment(args: object) -> DeploymentEnvironment | None:
    """Accept the single Telegram deployment environment: staging."""

    if not isinstance(args, (list, tuple)) or len(args) != 1 or not isinstance(args[0], str):
        return None

    if args[0] != DeploymentEnvironment.STAGING.value:
        return None

    return DeploymentEnvironment.STAGING


def _target_from_settings(
    settings: GitLabWriteSettings,
    environment: DeploymentEnvironment,
) -> ActionTarget:
    """Bind confirmation to the exact project, ref, and environment."""

    return ActionTarget(
        project_id=settings.project_id,
        ref=settings.allowed_ref,
        environment=environment,
    )


def _parse_callback(
    value: object,
) -> tuple[DeploymentEnvironment, str] | None:
    """Parse one bounded server-generated callback."""

    if not isinstance(value, str):
        return None

    match = re.fullmatch(DEPLOY_CALLBACK_PATTERN, value)
    if match is None:
        return None

    return (
        DeploymentEnvironment(match.group("environment")),
        match.group("token"),
    )


def _confirmation_message(
    environment: DeploymentEnvironment,
    ref: str,
) -> str:
    """Return a bounded confirmation prompt."""

    return f"Confirm deployment to {environment.value} within 2 minutes. Ref: {ref}."


def _success_message(
    environment: DeploymentEnvironment,
    summary: PipelineSummary,
) -> str:
    """Return only validated non-sensitive pipeline fields."""

    return (
        f"GitLab {environment.value} deployment pipeline accepted. "
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
    """Emit a controlled deployment audit event."""

    try:
        emit_action_audit(
            user_id=user_id,
            action=ActionKind.DEPLOY,
            outcome=outcome,
            target=target,
        )
    except ActionAuditError:
        _LOGGER.error(DEPLOY_AUDIT_LOG_MESSAGE)
        return False

    return True


async def deploy_handler(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Create a fresh staging-bound confirmation without calling GitLab."""

    message = await base_handlers._authorized_message(
        update,
        BotCommand.DEPLOY,
    )
    if message is None:
        return

    user = update.effective_user
    if user is None:
        await message.reply_text(DEPLOY_UNAVAILABLE_MESSAGE)
        return

    environment = _parse_environment(getattr(context, "args", None))
    if environment is None:
        await message.reply_text(
            DEPLOY_USAGE_MESSAGE,
            protect_content=True,
        )
        return

    try:
        settings = get_gitlab_write_settings()
        target = _target_from_settings(settings, environment)
        token = action_confirmation_store.issue(
            user_id=user.id,
            action=ActionKind.DEPLOY,
            target=target,
        )
    except (
        GitLabWriteConfigurationError,
        ActionConfirmationError,
    ):
        _LOGGER.error(DEPLOY_LOG_MESSAGE)
        await message.reply_text(DEPLOY_UNAVAILABLE_MESSAGE)
        return

    if not _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.REQUESTED,
        target=target,
    ):
        await message.reply_text(DEPLOY_UNAVAILABLE_MESSAGE)
        return

    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    DEPLOY_CONFIRMATION_BUTTON,
                    callback_data=(f"{DEPLOY_CALLBACK_PREFIX}{environment.value}:{token}"),
                )
            ]
        ]
    )

    await message.reply_text(
        _confirmation_message(environment, settings.allowed_ref),
        reply_markup=keyboard,
        protect_content=True,
        link_preview_options=DISABLED_DEPLOY_LINK_PREVIEW,
    )


async def deploy_staging_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Request the fixed staging deployment from a clickable command."""

    class _StagingContext:
        args = [DeploymentEnvironment.STAGING.value]

    await deploy_handler(update, _StagingContext())  # type: ignore[arg-type]


async def deploy_confirmation_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Start one staging deployment after a matching one-time confirmation."""

    query = update.callback_query
    if query is None:
        return

    await query.answer()

    message = await base_handlers._authorized_message(
        update,
        BotCommand.DEPLOY,
    )
    if message is None:
        return

    user = update.effective_user
    if user is None:
        await message.reply_text(DEPLOY_UNAVAILABLE_MESSAGE)
        return

    parsed = _parse_callback(query.data)
    if parsed is None:
        await message.reply_text(
            DEPLOY_INVALID_CONFIRMATION_MESSAGE,
            protect_content=True,
            link_preview_options=DISABLED_DEPLOY_LINK_PREVIEW,
        )
        return

    environment, token = parsed

    try:
        settings = get_gitlab_write_settings()
        target = _target_from_settings(settings, environment)
    except (
        GitLabWriteConfigurationError,
        ActionConfirmationError,
    ):
        _LOGGER.error(DEPLOY_LOG_MESSAGE)
        await message.reply_text(DEPLOY_UNAVAILABLE_MESSAGE)
        return

    if not action_confirmation_store.claim(
        token,
        user_id=user.id,
        action=ActionKind.DEPLOY,
        target=target,
    ):
        _emit_audit(
            user_id=user.id,
            outcome=ActionAuditOutcome.DENIED,
            target=target,
        )
        await message.reply_text(
            DEPLOY_INVALID_CONFIRMATION_MESSAGE,
            protect_content=True,
            link_preview_options=DISABLED_DEPLOY_LINK_PREVIEW,
        )
        return

    if not _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.CONFIRMED,
        target=target,
    ):
        await message.reply_text(DEPLOY_UNAVAILABLE_MESSAGE)
        return

    try:
        client = _build_gitlab_write_client(settings)
        summary = await client.run_deployment(environment)
    except GitLabClientError:
        _emit_audit(
            user_id=user.id,
            outcome=ActionAuditOutcome.FAILED,
            target=target,
        )
        _LOGGER.error(DEPLOY_LOG_MESSAGE)
        await message.reply_text(DEPLOY_UNAVAILABLE_MESSAGE)
        return

    _emit_audit(
        user_id=user.id,
        outcome=ActionAuditOutcome.SUCCEEDED,
        target=target,
    )

    await message.reply_text(
        _success_message(environment, summary),
        protect_content=True,
        link_preview_options=DISABLED_DEPLOY_LINK_PREVIEW,
    )

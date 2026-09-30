"""Safe fallback and centralized error handling for Telegram updates."""

import logging

from telegram import Message, Update
from telegram.ext import ContextTypes

from bot.authorization import is_user_allowed
from bot.config import BotConfigurationError, get_bot_settings
from bot.handlers import ACCESS_DENIED_MESSAGE, SERVICE_UNAVAILABLE_MESSAGE

UNKNOWN_COMMAND_MESSAGE = "Unknown command."
ERROR_LOG_MESSAGE = "Telegram update processing failed."

_LOGGER = logging.getLogger(__name__)


async def _allowlisted_message(update: Update) -> Message | None:
    """Return the message only when its Telegram identity is allowlisted."""

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

    if not is_user_allowed(user_id, settings.allowed_user_ids):
        await message.reply_text(ACCESS_DENIED_MESSAGE)
        return None

    return message


async def unknown_command_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Respond safely to unknown commands from allowlisted identities."""

    message = await _allowlisted_message(update)

    if message is not None:
        await message.reply_text(UNKNOWN_COMMAND_MESSAGE)


async def error_handler(
    update: object | None,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Log a static event and return a generic error response when possible."""

    error = getattr(_context, "error", None)
    error_type = type(error).__name__ if error is not None else "Unknown"
    _LOGGER.error("%s Type: %s", ERROR_LOG_MESSAGE, error_type)

    if not isinstance(update, Update):
        return

    message = update.effective_message

    if message is not None:
        await message.reply_text(SERVICE_UNAVAILABLE_MESSAGE)

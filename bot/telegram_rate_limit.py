"""Bounded Telegram update throttling."""

from telegram import Update
from telegram.ext import ApplicationHandlerStop, ContextTypes

from bot.config import MAX_TELEGRAM_USER_ID
from bot.rate_limit import BoundedRateLimiter

TELEGRAM_RATE_LIMIT_MAX_REQUESTS = 10
TELEGRAM_RATE_LIMIT_WINDOW_SECONDS = 10.0
TELEGRAM_RATE_LIMIT_MAX_IDENTITIES = 1_024

telegram_rate_limiter = BoundedRateLimiter(
    maximum_requests=TELEGRAM_RATE_LIMIT_MAX_REQUESTS,
    window_seconds=TELEGRAM_RATE_LIMIT_WINDOW_SECONDS,
    maximum_entries=TELEGRAM_RATE_LIMIT_MAX_IDENTITIES,
)


def _is_control_update(update: Update) -> bool:
    if update.callback_query is not None:
        return True

    message = update.effective_message
    text = getattr(message, "text", None)

    return isinstance(text, str) and text.startswith("/")


async def telegram_rate_limit_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Stop excessive command/callback updates before command handlers run."""

    if not _is_control_update(update):
        return

    user = update.effective_user

    if (
        user is None
        or isinstance(user.id, bool)
        or not isinstance(user.id, int)
        or user.id <= 0
        or user.id > MAX_TELEGRAM_USER_ID
    ):
        raise ApplicationHandlerStop

    if not telegram_rate_limiter.allow(f"telegram:{user.id}"):
        raise ApplicationHandlerStop

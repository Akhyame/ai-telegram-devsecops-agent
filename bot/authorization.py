"""Deny-by-default authorization for Telegram user identities."""

from bot.config import MAX_TELEGRAM_USER_ID


def is_user_allowed(
    user_id: object,
    allowed_user_ids: frozenset[int],
) -> bool:
    """Return whether a valid Telegram user ID is explicitly allowed."""

    if isinstance(user_id, bool) or not isinstance(user_id, int):
        return False

    if user_id <= 0 or user_id > MAX_TELEGRAM_USER_ID:
        return False

    return user_id in allowed_user_ids

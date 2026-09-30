"""Tests for deny-by-default Telegram identity authorization."""

import pytest

from bot.authorization import is_user_allowed
from bot.config import MAX_TELEGRAM_USER_ID

_ALLOWED_USER_ID = 123_456_789
_UNKNOWN_USER_ID = 987_654_321


def test_empty_allowlist_denies_valid_user() -> None:
    assert not is_user_allowed(_ALLOWED_USER_ID, frozenset())


def test_explicitly_allowed_user_is_allowed() -> None:
    allowed_user_ids = frozenset({_ALLOWED_USER_ID})

    assert is_user_allowed(_ALLOWED_USER_ID, allowed_user_ids)


def test_unknown_user_is_denied() -> None:
    allowed_user_ids = frozenset({_ALLOWED_USER_ID})

    assert not is_user_allowed(_UNKNOWN_USER_ID, allowed_user_ids)


def test_maximum_supported_user_id_can_be_allowed() -> None:
    allowed_user_ids = frozenset({MAX_TELEGRAM_USER_ID})

    assert is_user_allowed(MAX_TELEGRAM_USER_ID, allowed_user_ids)


@pytest.mark.parametrize(
    "invalid_user_id",
    [
        None,
        True,
        False,
        "123456789",
        123456789.0,
        0,
        -1,
        MAX_TELEGRAM_USER_ID + 1,
    ],
    ids=[
        "missing",
        "true-boolean",
        "false-boolean",
        "string",
        "float",
        "zero",
        "negative",
        "above-52-bit-limit",
    ],
)
def test_invalid_user_identity_is_denied(
    invalid_user_id: object,
) -> None:
    allowed_user_ids = frozenset(
        {
            0,
            1,
            _ALLOWED_USER_ID,
            MAX_TELEGRAM_USER_ID + 1,
        }
    )

    assert not is_user_allowed(invalid_user_id, allowed_user_ids)

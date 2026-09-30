"""Tests for secure Telegram bot configuration."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from bot.config import (
    MAX_TELEGRAM_USER_ID,
    BotConfigurationError,
    BotSettings,
    get_bot_settings,
)


def _valid_token() -> str:
    return "123456789:" + ("A" * 32)


@pytest.fixture(autouse=True)
def _isolate_bot_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_ALLOWED_USER_IDS", raising=False)
    monkeypatch.delenv("TELEGRAM_OPERATOR_USER_IDS", raising=False)
    monkeypatch.delenv("TELEGRAM_ADMIN_USER_IDS", raising=False)
    get_bot_settings.cache_clear()

    yield

    get_bot_settings.cache_clear()


def test_get_bot_settings_loads_token_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _valid_token()
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", expected)

    settings = get_bot_settings()

    assert isinstance(settings.token, SecretStr)
    assert settings.token.get_secret_value() == expected


def test_get_bot_settings_loads_token_from_ignored_dotenv() -> None:
    expected = _valid_token()
    Path(".env").write_text(
        f"TELEGRAM_BOT_TOKEN={expected}\n",
        encoding="utf-8",
    )

    settings = get_bot_settings()

    assert settings.token.get_secret_value() == expected


def test_get_bot_settings_rejects_missing_token_safely() -> None:
    with pytest.raises(
        BotConfigurationError,
        match=r"\ATelegram bot configuration is invalid\.\Z",
    ):
        get_bot_settings()


@pytest.mark.parametrize(
    "invalid_value",
    [
        "",
        "123456789-no-colon",
        "not-numeric:" + ("A" * 32),
        "123456789:short",
        "123456789:" + ("A" * 19),
        "123456789:" + ("A" * 201),
        "123456789:" + ("A" * 31) + " ",
    ],
    ids=[
        "empty",
        "missing-colon",
        "non-numeric-identifier",
        "short-secret",
        "below-minimum-secret-length",
        "above-maximum-secret-length",
        "trailing-whitespace",
    ],
)
def test_get_bot_settings_rejects_invalid_token_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch,
    invalid_value: str,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", invalid_value)

    with pytest.raises(BotConfigurationError) as exc_info:
        get_bot_settings()

    assert str(exc_info.value) == "Telegram bot configuration is invalid."
    if invalid_value:
        assert invalid_value not in str(exc_info.value)


def test_direct_validation_error_hides_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_value = "DO-NOT-PROPAGATE-THIS-VALUE"
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", invalid_value)

    with pytest.raises(ValidationError) as exc_info:
        BotSettings()

    assert invalid_value not in str(exc_info.value)


def test_settings_representation_masks_valid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _valid_token()
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", expected)

    settings = get_bot_settings()

    assert expected not in repr(settings)
    assert "**********" in repr(settings)


def test_allowed_user_ids_default_to_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())

    settings = get_bot_settings()

    assert settings.allowed_user_ids == frozenset()


def test_allowed_user_ids_parse_comma_separated_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())
    monkeypatch.setenv(
        "TELEGRAM_ALLOWED_USER_IDS",
        "123456789, 987654321, 4503599627370495",
    )

    settings = get_bot_settings()

    assert settings.allowed_user_ids == frozenset(
        {
            123456789,
            987654321,
            MAX_TELEGRAM_USER_ID,
        }
    )


@pytest.mark.parametrize(
    "invalid_value",
    [
        "   ",
        ",123456789",
        "123456789,",
        "123456789,,987654321",
        "0",
        "-1",
        "+1",
        "0123456789",
        "1.5",
        "１２３",
        "123456789,123456789",
        "4503599627370496",
    ],
    ids=[
        "whitespace-only",
        "missing-first-item",
        "missing-last-item",
        "empty-middle-item",
        "zero",
        "negative",
        "plus-sign",
        "leading-zero",
        "decimal",
        "unicode-digits",
        "duplicate",
        "above-52-bit-limit",
    ],
)
def test_allowed_user_ids_reject_invalid_values_without_leaking_them(
    monkeypatch: pytest.MonkeyPatch,
    invalid_value: str,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())
    monkeypatch.setenv("TELEGRAM_ALLOWED_USER_IDS", invalid_value)

    with pytest.raises(BotConfigurationError) as exc_info:
        get_bot_settings()

    assert str(exc_info.value) == "Telegram bot configuration is invalid."
    assert invalid_value not in str(exc_info.value)


def test_role_assignments_default_to_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())
    monkeypatch.setenv("TELEGRAM_ALLOWED_USER_IDS", "111111111")

    settings = get_bot_settings()

    assert settings.operator_user_ids == frozenset()
    assert settings.admin_user_ids == frozenset()


def test_role_assignments_parse_valid_subsets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())
    monkeypatch.setenv(
        "TELEGRAM_ALLOWED_USER_IDS",
        "111111111,222222222,333333333",
    )
    monkeypatch.setenv("TELEGRAM_OPERATOR_USER_IDS", "222222222")
    monkeypatch.setenv("TELEGRAM_ADMIN_USER_IDS", "333333333")

    settings = get_bot_settings()

    assert settings.operator_user_ids == frozenset({222222222})
    assert settings.admin_user_ids == frozenset({333333333})


def test_allowed_user_without_privileged_assignment_remains_valid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())
    monkeypatch.setenv("TELEGRAM_ALLOWED_USER_IDS", "111111111")

    settings = get_bot_settings()

    assert 111111111 in settings.allowed_user_ids
    assert 111111111 not in settings.operator_user_ids
    assert 111111111 not in settings.admin_user_ids


@pytest.mark.parametrize(
    (
        "allowed_user_ids",
        "operator_user_ids",
        "admin_user_ids",
    ),
    [
        ("111111111", "222222222", ""),
        ("111111111", "", "222222222"),
        ("111111111", "111111111", "111111111"),
        ("111111111", "not-an-id", ""),
    ],
    ids=[
        "operator-outside-allowlist",
        "admin-outside-allowlist",
        "ambiguous-privileged-role",
        "invalid-role-list",
    ],
)
def test_invalid_role_assignments_fail_closed_without_leaking_values(
    monkeypatch: pytest.MonkeyPatch,
    allowed_user_ids: str,
    operator_user_ids: str,
    admin_user_ids: str,
) -> None:
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", _valid_token())
    monkeypatch.setenv("TELEGRAM_ALLOWED_USER_IDS", allowed_user_ids)
    monkeypatch.setenv("TELEGRAM_OPERATOR_USER_IDS", operator_user_ids)
    monkeypatch.setenv("TELEGRAM_ADMIN_USER_IDS", admin_user_ids)

    with pytest.raises(BotConfigurationError) as exc_info:
        get_bot_settings()

    assert str(exc_info.value) == "Telegram bot configuration is invalid."

    for configured_value in (
        allowed_user_ids,
        operator_user_ids,
        admin_user_ids,
    ):
        if configured_value:
            assert configured_value not in str(exc_info.value)

"""Tests for deterministic Telegram role-based access control."""

import pytest

from bot.config import MAX_TELEGRAM_USER_ID
from bot.rbac import (
    BotCommand,
    Role,
    is_command_allowed,
    is_user_command_allowed,
    resolve_user_role,
)

_VIEWER_USER_ID = 101
_OPERATOR_USER_ID = 202
_ADMIN_USER_ID = 303
_UNKNOWN_USER_ID = 404

_ALLOWED_USER_IDS = frozenset(
    {
        1,
        _VIEWER_USER_ID,
        _OPERATOR_USER_ID,
        _ADMIN_USER_ID,
        MAX_TELEGRAM_USER_ID,
    }
)
_OPERATOR_USER_IDS = frozenset({_OPERATOR_USER_ID})
_ADMIN_USER_IDS = frozenset({1, _ADMIN_USER_ID})


def test_role_values_are_stable() -> None:
    assert tuple(Role) == (
        Role.VIEWER,
        Role.OPERATOR,
        Role.ADMIN,
    )
    assert tuple(role.value for role in Role) == (
        "viewer",
        "operator",
        "admin",
    )


@pytest.mark.parametrize(
    ("user_id", "expected_role"),
    [
        (_VIEWER_USER_ID, Role.VIEWER),
        (_OPERATOR_USER_ID, Role.OPERATOR),
        (_ADMIN_USER_ID, Role.ADMIN),
    ],
    ids=[
        "viewer",
        "operator",
        "admin",
    ],
)
def test_resolve_user_role(
    user_id: int,
    expected_role: Role,
) -> None:
    role = resolve_user_role(
        user_id,
        allowed_user_ids=_ALLOWED_USER_IDS,
        operator_user_ids=_OPERATOR_USER_IDS,
        admin_user_ids=_ADMIN_USER_IDS,
    )

    assert role is expected_role


@pytest.mark.parametrize(
    "invalid_user_id",
    [
        None,
        True,
        False,
        "101",
        101.0,
        0,
        -1,
        MAX_TELEGRAM_USER_ID + 1,
        _UNKNOWN_USER_ID,
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
        "unknown",
    ],
)
def test_resolve_user_role_denies_invalid_or_unknown_identity(
    invalid_user_id: object,
) -> None:
    role = resolve_user_role(
        invalid_user_id,
        allowed_user_ids=_ALLOWED_USER_IDS,
        operator_user_ids=_OPERATOR_USER_IDS,
        admin_user_ids=_ADMIN_USER_IDS,
    )

    assert role is None


def test_resolve_user_role_denies_ambiguous_assignment() -> None:
    role = resolve_user_role(
        _OPERATOR_USER_ID,
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=frozenset({_OPERATOR_USER_ID}),
        admin_user_ids=frozenset({_OPERATOR_USER_ID}),
    )

    assert role is None


@pytest.mark.parametrize(
    ("operator_user_ids", "admin_user_ids"),
    [
        (frozenset({_UNKNOWN_USER_ID}), frozenset()),
        (frozenset(), frozenset({_UNKNOWN_USER_ID})),
    ],
    ids=[
        "operator-outside-allowlist",
        "admin-outside-allowlist",
    ],
)
def test_resolve_user_role_denies_privileged_identity_outside_allowlist(
    operator_user_ids: frozenset[int],
    admin_user_ids: frozenset[int],
) -> None:
    role = resolve_user_role(
        _UNKNOWN_USER_ID,
        allowed_user_ids=frozenset({_VIEWER_USER_ID}),
        operator_user_ids=operator_user_ids,
        admin_user_ids=admin_user_ids,
    )

    assert role is None


@pytest.mark.parametrize(
    ("role", "allowed_commands"),
    [
        (
            Role.VIEWER,
            frozenset(
                {
                    BotCommand.START,
                    BotCommand.HELP,
                    BotCommand.STATUS,
                }
            ),
        ),
        (
            Role.OPERATOR,
            frozenset(
                {
                    BotCommand.START,
                    BotCommand.HELP,
                    BotCommand.STATUS,
                    BotCommand.LOGS,
                    BotCommand.EXPLAIN,
                    BotCommand.EXPLAIN_SECURITY,
                    BotCommand.RUN_PIPELINE,
                    BotCommand.RETRY_PIPELINE,
                    BotCommand.SCAN,
                }
            ),
        ),
        (
            Role.ADMIN,
            frozenset(BotCommand),
        ),
    ],
    ids=[
        "viewer-permissions",
        "operator-permissions",
        "admin-permissions",
    ],
)
def test_role_command_permissions_are_exact(
    role: Role,
    allowed_commands: frozenset[BotCommand],
) -> None:
    for command in BotCommand:
        assert is_command_allowed(role, command) is (command in allowed_commands)


@pytest.mark.parametrize(
    ("role", "command"),
    [
        (None, BotCommand.STATUS),
        ("admin", BotCommand.STATUS),
        (Role.ADMIN, None),
        (Role.ADMIN, "deploy"),
        (Role.ADMIN, True),
    ],
    ids=[
        "missing-role",
        "untyped-role",
        "missing-command",
        "untyped-command",
        "boolean-command",
    ],
)
def test_command_authorization_denies_untyped_inputs(
    role: object,
    command: object,
) -> None:
    assert not is_command_allowed(role, command)


@pytest.mark.parametrize(
    ("user_id", "command", "expected"),
    [
        (_VIEWER_USER_ID, BotCommand.STATUS, True),
        (_VIEWER_USER_ID, BotCommand.LOGS, False),
        (_OPERATOR_USER_ID, BotCommand.LOGS, True),
        (_OPERATOR_USER_ID, BotCommand.RETRY_PIPELINE, True),
        (_OPERATOR_USER_ID, BotCommand.CANCEL_PIPELINE, False),
        (_OPERATOR_USER_ID, BotCommand.DEPLOY, False),
        (_ADMIN_USER_ID, BotCommand.CANCEL_PIPELINE, True),
        (_ADMIN_USER_ID, BotCommand.DEPLOY, True),
        (_UNKNOWN_USER_ID, BotCommand.START, False),
    ],
    ids=[
        "viewer-status-allowed",
        "viewer-logs-denied",
        "operator-logs-allowed",
        "operator-retry-allowed",
        "operator-cancel-denied",
        "operator-deploy-denied",
        "admin-cancel-allowed",
        "admin-deploy-allowed",
        "unknown-start-denied",
    ],
)
def test_user_command_authorization_gateway(
    user_id: int,
    command: BotCommand,
    expected: bool,
) -> None:
    result = is_user_command_allowed(
        user_id,
        command,
        allowed_user_ids=_ALLOWED_USER_IDS,
        operator_user_ids=_OPERATOR_USER_IDS,
        admin_user_ids=_ADMIN_USER_IDS,
    )

    assert result is expected

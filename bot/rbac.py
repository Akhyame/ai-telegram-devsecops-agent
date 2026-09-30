"""Deterministic role-based access control for Telegram commands."""

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType

from bot.authorization import is_user_allowed


class Role(StrEnum):
    """Supported Telegram authorization roles."""

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class BotCommand(StrEnum):
    """Telegram bot commands governed by the RBAC policy."""

    START = "start"
    HELP = "help"
    STATUS = "status"
    LOGS = "logs"
    EXPLAIN = "explain"
    EXPLAIN_SECURITY = "explain_security"
    RUN_PIPELINE = "run_pipeline"
    CANCEL_PIPELINE = "cancel_pipeline"
    RETRY_PIPELINE = "retry_pipeline"
    SCAN = "scan"
    DEPLOY = "deploy"


_VIEWER_COMMANDS = frozenset(
    {
        BotCommand.START,
        BotCommand.HELP,
        BotCommand.STATUS,
    }
)

_OPERATOR_COMMANDS = _VIEWER_COMMANDS | frozenset(
    {
        BotCommand.LOGS,
        BotCommand.EXPLAIN,
        BotCommand.EXPLAIN_SECURITY,
        BotCommand.RUN_PIPELINE,
        BotCommand.RETRY_PIPELINE,
        BotCommand.SCAN,
    }
)

_ADMIN_COMMANDS = _OPERATOR_COMMANDS | frozenset(
    {
        BotCommand.CANCEL_PIPELINE,
        BotCommand.DEPLOY,
    }
)

_ROLE_PERMISSIONS: Mapping[Role, frozenset[BotCommand]] = MappingProxyType(
    {
        Role.VIEWER: _VIEWER_COMMANDS,
        Role.OPERATOR: _OPERATOR_COMMANDS,
        Role.ADMIN: _ADMIN_COMMANDS,
    }
)


def resolve_user_role(
    user_id: object,
    *,
    allowed_user_ids: frozenset[int],
    operator_user_ids: frozenset[int],
    admin_user_ids: frozenset[int],
) -> Role | None:
    """Resolve one explicit role or deny an invalid or ambiguous identity."""

    if not is_user_allowed(user_id, allowed_user_ids):
        return None

    is_operator = user_id in operator_user_ids
    is_admin = user_id in admin_user_ids

    if is_operator and is_admin:
        return None

    if is_admin:
        return Role.ADMIN

    if is_operator:
        return Role.OPERATOR

    return Role.VIEWER


def is_command_allowed(
    role: object,
    command: object,
) -> bool:
    """Return whether a typed role may execute a typed command."""

    if not isinstance(role, Role) or not isinstance(command, BotCommand):
        return False

    return command in _ROLE_PERMISSIONS.get(role, frozenset())


def is_user_command_allowed(
    user_id: object,
    command: object,
    *,
    allowed_user_ids: frozenset[int],
    operator_user_ids: frozenset[int],
    admin_user_ids: frozenset[int],
) -> bool:
    """Apply identity validation, role resolution, and command authorization."""

    role = resolve_user_role(
        user_id,
        allowed_user_ids=allowed_user_ids,
        operator_user_ids=operator_user_ids,
        admin_user_ids=admin_user_ids,
    )

    return is_command_allowed(role, command)

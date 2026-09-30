"""Structured and secret-safe audit events for Telegram actions."""

import logging
from enum import StrEnum

from bot.action_confirmation import (
    ActionKind,
    ActionTarget,
)
from bot.config import MAX_TELEGRAM_USER_ID

ACTION_AUDIT_LOG_MESSAGE = "Telegram action audit event."


class ActionAuditOutcome(StrEnum):
    """Controlled outcomes for a mutating action lifecycle."""

    REQUESTED = "requested"
    CONFIRMED = "confirmed"
    DENIED = "denied"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ActionAuditError(RuntimeError):
    """Static failure for invalid audit input."""


_LOGGER = logging.getLogger(__name__)


def emit_action_audit(
    *,
    user_id: int,
    action: ActionKind,
    outcome: ActionAuditOutcome,
    target: ActionTarget,
) -> None:
    """Emit one controlled event without tokens or error details."""

    if not _valid_event(
        user_id=user_id,
        action=action,
        outcome=outcome,
        target=target,
    ):
        raise ActionAuditError("Action audit failed.")

    _LOGGER.info(
        ACTION_AUDIT_LOG_MESSAGE,
        extra={
            "audit_event": "telegram_action",
            "audit_actor_user_id": user_id,
            "audit_action": action.value,
            "audit_outcome": outcome.value,
            "audit_project_id": target.project_id,
            "audit_ref": target.ref,
            "audit_pipeline_id": target.pipeline_id,
            "audit_environment": (
                target.environment.value if target.environment is not None else None
            ),
        },
    )


def _valid_event(
    *,
    user_id: object,
    action: object,
    outcome: object,
    target: object,
) -> bool:
    if (
        isinstance(user_id, bool)
        or not isinstance(user_id, int)
        or user_id <= 0
        or user_id > MAX_TELEGRAM_USER_ID
        or not isinstance(action, ActionKind)
        or not isinstance(outcome, ActionAuditOutcome)
        or not isinstance(target, ActionTarget)
    ):
        return False

    requires_pipeline = action in {
        ActionKind.CANCEL_PIPELINE,
        ActionKind.RETRY_PIPELINE,
    }

    if requires_pipeline:
        return target.pipeline_id is not None and target.environment is None

    if action is ActionKind.DEPLOY:
        return target.pipeline_id is None and target.environment is not None

    return target.pipeline_id is None and target.environment is None

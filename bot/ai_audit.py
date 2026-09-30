"""Structured and content-free audit events for local AI interactions."""

import logging
from enum import StrEnum

from agent.models import FailureCode, PipelineJob
from bot.config import MAX_TELEGRAM_USER_ID

AI_AUDIT_LOG_MESSAGE = "Telegram AI audit event."


class AIAuditTask(StrEnum):
    """Controlled local AI tasks exposed through Telegram."""

    EXPLAIN_FAILURE = "explain_failure"
    EXPLAIN_SECURITY_SCAN = "explain_security_scan"


class AIAuditOutcome(StrEnum):
    """Controlled outcomes for a local AI interaction."""

    REQUESTED = "requested"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class AIAuditFailure(StrEnum):
    """Controlled, content-free failure categories."""

    GITLAB_UNAVAILABLE = "gitlab_unavailable"
    NORMALIZATION_FAILED = "normalization_failed"
    AI_CONFIGURATION_INVALID = "ai_configuration_invalid"
    AI_NETWORK = "ai_network"
    AI_TIMEOUT = "ai_timeout"
    AI_UNAVAILABLE = "ai_unavailable"
    AI_INVALID_RESPONSE = "ai_invalid_response"


class AIAuditError(RuntimeError):
    """Static failure for invalid AI audit input."""


_LOGGER = logging.getLogger(__name__)


def emit_ai_audit(
    *,
    user_id: int,
    task: AIAuditTask,
    outcome: AIAuditOutcome,
    job: PipelineJob | None = None,
    failure_code: FailureCode | None = None,
    failure: AIAuditFailure | None = None,
) -> None:
    """Emit metadata only, without prompts, logs, or model output."""

    if not _valid_event(
        user_id=user_id,
        task=task,
        outcome=outcome,
        job=job,
        failure_code=failure_code,
        failure=failure,
    ):
        raise AIAuditError("AI audit failed.")

    _LOGGER.info(
        AI_AUDIT_LOG_MESSAGE,
        extra={
            "audit_event": "telegram_ai",
            "audit_actor_user_id": user_id,
            "audit_ai_task": task.value,
            "audit_outcome": outcome.value,
            "audit_job": None if job is None else job.value,
            "audit_failure_code": (None if failure_code is None else failure_code.value),
            "audit_error_category": (None if failure is None else failure.value),
        },
    )


def _valid_event(
    *,
    user_id: object,
    task: object,
    outcome: object,
    job: object,
    failure_code: object,
    failure: object,
) -> bool:
    if (
        isinstance(user_id, bool)
        or not isinstance(user_id, int)
        or user_id <= 0
        or user_id > MAX_TELEGRAM_USER_ID
        or not isinstance(task, AIAuditTask)
        or not isinstance(outcome, AIAuditOutcome)
        or (job is not None and not isinstance(job, PipelineJob))
        or (failure_code is not None and not isinstance(failure_code, FailureCode))
        or (failure is not None and not isinstance(failure, AIAuditFailure))
    ):
        return False

    if (job is None) is not (failure_code is None):
        return False

    if task is AIAuditTask.EXPLAIN_SECURITY_SCAN and (job is not None or failure_code is not None):
        return False

    if outcome is AIAuditOutcome.FAILED:
        return failure is not None

    if failure is not None:
        return False

    if task is AIAuditTask.EXPLAIN_FAILURE:
        return job is not None and failure_code is not None

    return job is None and failure_code is None

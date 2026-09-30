"""Authorized Telegram handler for bounded local AI explanations."""

import logging

from telegram import Message, Update
from telegram.ext import ContextTypes

from agent.client import (
    AIClientError,
    AIErrorKind,
    LocalAIClient,
)
from agent.config import (
    AIConfigurationError,
    get_ai_settings,
)
from agent.models import (
    FailureExplanation,
    NormalizedFailure,
)
from agent.normalizer import (
    FailureNormalizationError,
    normalize_job_failure,
)
from agent.security_models import (
    NormalizedSecurityScan,
    SecurityScanExplanation,
)
from bot.ai_audit import (
    AIAuditError,
    AIAuditFailure,
    AIAuditOutcome,
    AIAuditTask,
    emit_ai_audit,
)
from bot.gitlab_client import GitLabClientError
from bot.gitlab_config import (
    GitLabConfigurationError,
    get_gitlab_settings,
)
from bot.handlers import (
    DISABLED_LOG_LINK_PREVIEW,
    _authorized_message,
    _build_gitlab_log_client,
)
from bot.rbac import BotCommand
from bot.security_scan_results import GitLabSecurityScanResultClient

AI_EXPLANATION_WAIT_MESSAGE = "Analyzing the latest failed pipeline. Please wait..."
AI_SECURITY_EXPLANATION_WAIT_MESSAGE = "Analyzing the latest security scan. Please wait..."
AI_EXPLANATION_USAGE_MESSAGE = "Usage: /explain, /explain security, or /explain_security."
AI_EXPLANATION_UNAVAILABLE_MESSAGE = "AI explanation is unavailable."
AI_EXPLANATION_PREFIX = "Latest failed pipeline explanation:"
AI_SECURITY_EXPLANATION_PREFIX = "Latest security scan explanation:"
AI_EXPLANATION_GITLAB_LOG_MESSAGE = "GitLab failure retrieval for AI explanation failed."
AI_SECURITY_EXPLANATION_GITLAB_LOG_MESSAGE = (
    "GitLab Security Gate retrieval for AI explanation failed."
)
AI_EXPLANATION_NORMALIZATION_LOG_MESSAGE = (
    "Pipeline failure normalization for AI explanation failed."
)
AI_EXPLANATION_CLIENT_LOG_MESSAGE = "Local AI failure explanation request failed."
AI_SECURITY_EXPLANATION_CLIENT_LOG_MESSAGE = "Local AI security scan explanation request failed."
AI_EXPLANATION_AUDIT_LOG_MESSAGE = "Local AI interaction audit failed."

_AI_ERROR_AUDIT_FAILURES = {
    AIErrorKind.NETWORK: AIAuditFailure.AI_NETWORK,
    AIErrorKind.TIMEOUT: AIAuditFailure.AI_TIMEOUT,
    AIErrorKind.UNAVAILABLE: AIAuditFailure.AI_UNAVAILABLE,
    AIErrorKind.INVALID_RESPONSE: (AIAuditFailure.AI_INVALID_RESPONSE),
}

_LOGGER = logging.getLogger(__name__)


def _build_ai_client() -> LocalAIClient:
    """Build the fixed local-only Ollama client."""

    return LocalAIClient(get_ai_settings())


def _build_security_scan_result_client() -> GitLabSecurityScanResultClient:
    """Build the fixed-project read-only Security Gate client."""

    return GitLabSecurityScanResultClient(get_gitlab_settings())


def _explanation_message(
    failure: NormalizedFailure,
    explanation: FailureExplanation,
) -> str:
    """Format only validated normalized metadata and AI output."""

    return (
        f"{AI_EXPLANATION_PREFIX}\n"
        f"Job: {failure.job.value}\n"
        f"Failure code: {failure.failure_code.value}\n"
        f"Summary: {explanation.summary}\n"
        f"Likely cause: {explanation.likely_cause}\n"
        f"Safe next step: {explanation.safe_next_step}\n"
        f"Confidence: {explanation.confidence.value}"
    )


def _security_explanation_message(
    scan: NormalizedSecurityScan,
    explanation: SecurityScanExplanation,
) -> str:
    """Format only validated Security Gate metadata and AI output."""

    return (
        f"{AI_SECURITY_EXPLANATION_PREFIX}\n"
        f"Decision: {scan.decision.value}\n"
        f"Total findings: {scan.total_findings}\n"
        f"Blocking findings: {scan.blocking_findings}\n"
        f"Summary: {explanation.summary}\n"
        f"Risk: {explanation.risk_explanation}\n"
        f"Safe remediation: {explanation.safe_remediation}\n"
        f"Confidence: {explanation.confidence.value}"
    )


def _fallback_message(
    failure: NormalizedFailure,
) -> str:
    """Return deterministic metadata when local AI is unavailable."""

    return (
        f"{AI_EXPLANATION_UNAVAILABLE_MESSAGE} "
        f"Normalized job: {failure.job.value}. "
        f"Failure code: {failure.failure_code.value}. "
        "Safe next step: verify that Ollama is running locally, "
        "then retry /explain."
    )


def _security_fallback_message(
    scan: NormalizedSecurityScan,
) -> str:
    """Return deterministic Security Gate metadata if AI is unavailable."""

    return (
        f"{AI_EXPLANATION_UNAVAILABLE_MESSAGE} "
        f"Security decision: {scan.decision.value}. "
        f"Total findings: {scan.total_findings}. "
        f"Blocking findings: {scan.blocking_findings}. "
        "Safe next step: verify that Ollama is running locally, "
        "then retry /explain security."
    )


def _emit_failed_audit(
    *,
    user_id: int,
    failure: AIAuditFailure,
    normalized: NormalizedFailure | None = None,
) -> None:
    """Best-effort metadata-only audit for an already failed request."""

    try:
        emit_ai_audit(
            user_id=user_id,
            task=AIAuditTask.EXPLAIN_FAILURE,
            outcome=AIAuditOutcome.FAILED,
            job=None if normalized is None else normalized.job,
            failure_code=(None if normalized is None else normalized.failure_code),
            failure=failure,
        )
    except AIAuditError:
        _LOGGER.error(AI_EXPLANATION_AUDIT_LOG_MESSAGE)


def _emit_failed_security_audit(
    *,
    user_id: int,
    failure: AIAuditFailure,
) -> None:
    """Best-effort metadata-only security AI failure audit."""

    try:
        emit_ai_audit(
            user_id=user_id,
            task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
            outcome=AIAuditOutcome.FAILED,
            failure=failure,
        )
    except AIAuditError:
        _LOGGER.error(AI_EXPLANATION_AUDIT_LOG_MESSAGE)


async def _explain_security_scan(
    *,
    message: Message,
    user_id: int,
) -> None:
    """Explain only the normalized result of the latest Security Gate."""

    progress_message = await message.reply_text(AI_SECURITY_EXPLANATION_WAIT_MESSAGE)

    try:
        scan_client = _build_security_scan_result_client()
        scan = await scan_client.get_latest_security_scan()
    except (
        GitLabConfigurationError,
        GitLabClientError,
    ):
        _LOGGER.error(AI_SECURITY_EXPLANATION_GITLAB_LOG_MESSAGE)
        _emit_failed_security_audit(
            user_id=user_id,
            failure=AIAuditFailure.GITLAB_UNAVAILABLE,
        )
        await progress_message.edit_text(AI_EXPLANATION_UNAVAILABLE_MESSAGE)
        return

    try:
        emit_ai_audit(
            user_id=user_id,
            task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
            outcome=AIAuditOutcome.REQUESTED,
        )
    except AIAuditError:
        _LOGGER.error(AI_EXPLANATION_AUDIT_LOG_MESSAGE)
        await progress_message.edit_text(AI_EXPLANATION_UNAVAILABLE_MESSAGE)
        return

    try:
        ai_client = _build_ai_client()
        explanation = await ai_client.explain_security_scan(scan)
    except AIConfigurationError:
        _LOGGER.error(AI_SECURITY_EXPLANATION_CLIENT_LOG_MESSAGE)
        _emit_failed_security_audit(
            user_id=user_id,
            failure=AIAuditFailure.AI_CONFIGURATION_INVALID,
        )
        await progress_message.edit_text(
            _security_fallback_message(scan),
            link_preview_options=DISABLED_LOG_LINK_PREVIEW,
        )
        return
    except AIClientError as error:
        _LOGGER.error(AI_SECURITY_EXPLANATION_CLIENT_LOG_MESSAGE)
        audit_failure = _AI_ERROR_AUDIT_FAILURES.get(
            error.kind,
            AIAuditFailure.AI_INVALID_RESPONSE,
        )
        _emit_failed_security_audit(
            user_id=user_id,
            failure=audit_failure,
        )
        await progress_message.edit_text(
            _security_fallback_message(scan),
            link_preview_options=DISABLED_LOG_LINK_PREVIEW,
        )
        return

    try:
        emit_ai_audit(
            user_id=user_id,
            task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
            outcome=AIAuditOutcome.SUCCEEDED,
        )
    except AIAuditError:
        _LOGGER.error(AI_EXPLANATION_AUDIT_LOG_MESSAGE)
        await progress_message.edit_text(AI_EXPLANATION_UNAVAILABLE_MESSAGE)
        return

    await progress_message.edit_text(
        _security_explanation_message(
            scan,
            explanation,
        ),
        link_preview_options=DISABLED_LOG_LINK_PREVIEW,
    )


async def explain_security_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Explain the latest Security Gate through a standalone command."""

    message = await _authorized_message(
        update,
        BotCommand.EXPLAIN_SECURITY,
    )

    if message is None:
        return

    user = update.effective_user

    if user is None:
        return

    await _explain_security_scan(
        message=message,
        user_id=user.id,
    )


async def explain_handler(
    update: Update,
    _context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Explain the latest sanitized failed pipeline using local AI."""

    message = await _authorized_message(
        update,
        BotCommand.EXPLAIN,
    )

    if message is None:
        return

    user = update.effective_user

    if user is None:
        return

    user_id = user.id
    arguments = tuple(
        getattr(
            _context,
            "args",
            (),
        )
        or ()
    )

    if arguments:
        if arguments != ("security",):
            await message.reply_text(AI_EXPLANATION_USAGE_MESSAGE)
            return

        await _explain_security_scan(
            message=message,
            user_id=user_id,
        )
        return

    progress_message = await message.reply_text(AI_EXPLANATION_WAIT_MESSAGE)

    try:
        gitlab_client = _build_gitlab_log_client()
        summary = await gitlab_client.get_latest_failed_job_log()
    except (
        GitLabConfigurationError,
        GitLabClientError,
    ):
        _LOGGER.error(AI_EXPLANATION_GITLAB_LOG_MESSAGE)
        _emit_failed_audit(
            user_id=user_id,
            failure=AIAuditFailure.GITLAB_UNAVAILABLE,
        )
        await progress_message.edit_text(AI_EXPLANATION_UNAVAILABLE_MESSAGE)
        return

    try:
        normalized = normalize_job_failure(summary)
    except (
        FailureNormalizationError,
        TypeError,
    ):
        _LOGGER.error(AI_EXPLANATION_NORMALIZATION_LOG_MESSAGE)
        _emit_failed_audit(
            user_id=user_id,
            failure=AIAuditFailure.NORMALIZATION_FAILED,
        )
        await progress_message.edit_text(AI_EXPLANATION_UNAVAILABLE_MESSAGE)
        return

    try:
        emit_ai_audit(
            user_id=user_id,
            task=AIAuditTask.EXPLAIN_FAILURE,
            outcome=AIAuditOutcome.REQUESTED,
            job=normalized.job,
            failure_code=normalized.failure_code,
        )
    except AIAuditError:
        _LOGGER.error(AI_EXPLANATION_AUDIT_LOG_MESSAGE)
        await progress_message.edit_text(AI_EXPLANATION_UNAVAILABLE_MESSAGE)
        return

    try:
        ai_client = _build_ai_client()
        explanation = await ai_client.explain_failure(normalized)
    except AIConfigurationError:
        _LOGGER.error(AI_EXPLANATION_CLIENT_LOG_MESSAGE)
        _emit_failed_audit(
            user_id=user_id,
            failure=(AIAuditFailure.AI_CONFIGURATION_INVALID),
            normalized=normalized,
        )
        await progress_message.edit_text(
            _fallback_message(normalized),
            link_preview_options=(DISABLED_LOG_LINK_PREVIEW),
        )
        return
    except AIClientError as error:
        _LOGGER.error(AI_EXPLANATION_CLIENT_LOG_MESSAGE)
        audit_failure = _AI_ERROR_AUDIT_FAILURES.get(
            error.kind,
            AIAuditFailure.AI_INVALID_RESPONSE,
        )
        _emit_failed_audit(
            user_id=user_id,
            failure=audit_failure,
            normalized=normalized,
        )
        await progress_message.edit_text(
            _fallback_message(normalized),
            link_preview_options=(DISABLED_LOG_LINK_PREVIEW),
        )
        return

    try:
        emit_ai_audit(
            user_id=user_id,
            task=AIAuditTask.EXPLAIN_FAILURE,
            outcome=AIAuditOutcome.SUCCEEDED,
            job=normalized.job,
            failure_code=normalized.failure_code,
        )
    except AIAuditError:
        _LOGGER.error(AI_EXPLANATION_AUDIT_LOG_MESSAGE)
        await progress_message.edit_text(AI_EXPLANATION_UNAVAILABLE_MESSAGE)
        return

    await progress_message.edit_text(
        _explanation_message(
            normalized,
            explanation,
        ),
        link_preview_options=DISABLED_LOG_LINK_PREVIEW,
    )

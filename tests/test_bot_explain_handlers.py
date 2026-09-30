"""Offline security tests for the Telegram /explain handler."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest

import bot.explain_handlers as explain
import bot.handlers as base_handlers
from agent.client import AIClientError, AIErrorKind
from agent.config import AIConfigurationError
from agent.models import (
    Confidence,
    FailureCode,
    FailureExplanation,
    NormalizedFailure,
    PipelineJob,
)
from agent.normalizer import FailureNormalizationError
from bot.ai_audit import (
    AIAuditError,
    AIAuditFailure,
    AIAuditOutcome,
    AIAuditTask,
)
from bot.gitlab_client import (
    GitLabClientError,
    GitLabErrorKind,
)

_OPERATOR_USER_ID = 202


def _configure_role(
    monkeypatch: pytest.MonkeyPatch,
    *,
    operator: bool,
) -> None:
    settings = SimpleNamespace(
        allowed_user_ids=frozenset({_OPERATOR_USER_ID}),
        operator_user_ids=(frozenset({_OPERATOR_USER_ID}) if operator else frozenset()),
        admin_user_ids=frozenset(),
    )
    monkeypatch.setattr(
        base_handlers,
        "get_bot_settings",
        lambda: settings,
    )


def _make_update() -> tuple[
    SimpleNamespace,
    SimpleNamespace,
]:
    progress = SimpleNamespace(
        edit_text=AsyncMock(),
    )
    message = SimpleNamespace(
        reply_text=AsyncMock(
            return_value=progress,
        ),
        progress=progress,
    )
    update = SimpleNamespace(
        effective_user=SimpleNamespace(id=_OPERATOR_USER_ID),
        effective_message=message,
    )

    return update, message


def _normalized_failure() -> NormalizedFailure:
    return NormalizedFailure(
        job=PipelineJob.UNIT_TESTS,
        failure_code=FailureCode.UNIT_TESTS_FAILED,
    )


def _explanation() -> FailureExplanation:
    return FailureExplanation(
        summary="The unit test job failed.",
        likely_cause="A test assertion did not pass.",
        safe_next_step="Inspect the failed test result.",
        confidence=Confidence.HIGH,
    )


def _prepare_normalized_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    NormalizedFailure,
    SimpleNamespace,
    AsyncMock,
    Mock,
]:
    normalized = _normalized_failure()
    summary = SimpleNamespace(
        text="DO-NOT-FORWARD-TRACE",
    )
    gitlab_request = AsyncMock(return_value=summary)
    normalizer = Mock(return_value=normalized)

    monkeypatch.setattr(
        explain,
        "_build_gitlab_log_client",
        lambda: SimpleNamespace(get_latest_failed_job_log=gitlab_request),
    )
    monkeypatch.setattr(
        explain,
        "normalize_job_failure",
        normalizer,
    )

    return (
        normalized,
        summary,
        gitlab_request,
        normalizer,
    )


def test_explain_returns_only_validated_bounded_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(monkeypatch, operator=True)
    update, message = _make_update()
    (
        normalized,
        summary,
        gitlab_request,
        normalizer,
    ) = _prepare_normalized_flow(monkeypatch)
    explanation = _explanation()
    ai_request = AsyncMock(return_value=explanation)
    audit = Mock()

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        lambda: SimpleNamespace(explain_failure=ai_request),
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        audit,
    )

    asyncio.run(explain.explain_handler(update, object()))

    message.reply_text.assert_awaited_once_with(explain.AI_EXPLANATION_WAIT_MESSAGE)
    gitlab_request.assert_awaited_once_with()
    normalizer.assert_called_once_with(summary)
    ai_request.assert_awaited_once_with(normalized)
    audit.assert_has_calls(
        [
            call(
                user_id=_OPERATOR_USER_ID,
                task=AIAuditTask.EXPLAIN_FAILURE,
                outcome=AIAuditOutcome.REQUESTED,
                job=normalized.job,
                failure_code=(normalized.failure_code),
            ),
            call(
                user_id=_OPERATOR_USER_ID,
                task=AIAuditTask.EXPLAIN_FAILURE,
                outcome=AIAuditOutcome.SUCCEEDED,
                job=normalized.job,
                failure_code=(normalized.failure_code),
            ),
        ]
    )
    assert audit.call_count == 2

    expected = explain._explanation_message(
        normalized,
        explanation,
    )
    message.progress.edit_text.assert_awaited_once_with(
        expected,
        link_preview_options=(explain.DISABLED_LOG_LINK_PREVIEW),
    )
    assert summary.text not in expected
    assert summary.text not in str(ai_request.await_args)
    assert summary.text not in str(audit.call_args_list)


def test_viewer_cannot_use_explain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(monkeypatch, operator=False)
    update, message = _make_update()
    build_gitlab = Mock()

    monkeypatch.setattr(
        explain,
        "_build_gitlab_log_client",
        build_gitlab,
    )

    asyncio.run(explain.explain_handler(update, object()))

    message.reply_text.assert_awaited_once_with(base_handlers.ACCESS_DENIED_MESSAGE)
    message.progress.edit_text.assert_not_awaited()
    build_gitlab.assert_not_called()


def test_gitlab_failure_returns_generic_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(monkeypatch, operator=True)
    update, message = _make_update()
    gitlab_request = AsyncMock(side_effect=GitLabClientError(GitLabErrorKind.NETWORK))
    audit = Mock()

    monkeypatch.setattr(
        explain,
        "_build_gitlab_log_client",
        lambda: SimpleNamespace(get_latest_failed_job_log=gitlab_request),
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        audit,
    )

    asyncio.run(explain.explain_handler(update, object()))

    message.progress.edit_text.assert_awaited_once_with(explain.AI_EXPLANATION_UNAVAILABLE_MESSAGE)
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        task=AIAuditTask.EXPLAIN_FAILURE,
        outcome=AIAuditOutcome.FAILED,
        job=None,
        failure_code=None,
        failure=AIAuditFailure.GITLAB_UNAVAILABLE,
    )


def test_normalization_failure_never_calls_ai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(monkeypatch, operator=True)
    update, message = _make_update()
    summary = SimpleNamespace(text="sanitized trace")
    ai_builder = Mock()
    audit = Mock()

    monkeypatch.setattr(
        explain,
        "_build_gitlab_log_client",
        lambda: SimpleNamespace(get_latest_failed_job_log=AsyncMock(return_value=summary)),
    )
    monkeypatch.setattr(
        explain,
        "normalize_job_failure",
        Mock(side_effect=FailureNormalizationError("GitLab job failure cannot be normalized.")),
    )
    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        ai_builder,
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        audit,
    )

    asyncio.run(explain.explain_handler(update, object()))

    ai_builder.assert_not_called()
    message.progress.edit_text.assert_awaited_once_with(explain.AI_EXPLANATION_UNAVAILABLE_MESSAGE)
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        task=AIAuditTask.EXPLAIN_FAILURE,
        outcome=AIAuditOutcome.FAILED,
        job=None,
        failure_code=None,
        failure=AIAuditFailure.NORMALIZATION_FAILED,
    )


@pytest.mark.parametrize(
    ("error_kind", "audit_failure"),
    (
        (
            AIErrorKind.NETWORK,
            AIAuditFailure.AI_NETWORK,
        ),
        (
            AIErrorKind.TIMEOUT,
            AIAuditFailure.AI_TIMEOUT,
        ),
        (
            AIErrorKind.UNAVAILABLE,
            AIAuditFailure.AI_UNAVAILABLE,
        ),
        (
            AIErrorKind.INVALID_RESPONSE,
            AIAuditFailure.AI_INVALID_RESPONSE,
        ),
    ),
)
def test_ai_failure_uses_metadata_only_fallback(
    monkeypatch: pytest.MonkeyPatch,
    error_kind: AIErrorKind,
    audit_failure: AIAuditFailure,
) -> None:
    _configure_role(monkeypatch, operator=True)
    update, message = _make_update()
    normalized, _, _, _ = _prepare_normalized_flow(monkeypatch)
    ai_request = AsyncMock(side_effect=AIClientError(error_kind))
    audit = Mock()

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        lambda: SimpleNamespace(explain_failure=ai_request),
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        audit,
    )

    asyncio.run(explain.explain_handler(update, object()))

    message.progress.edit_text.assert_awaited_once_with(
        explain._fallback_message(normalized),
        link_preview_options=(explain.DISABLED_LOG_LINK_PREVIEW),
    )
    assert audit.call_args_list[-1] == call(
        user_id=_OPERATOR_USER_ID,
        task=AIAuditTask.EXPLAIN_FAILURE,
        outcome=AIAuditOutcome.FAILED,
        job=normalized.job,
        failure_code=normalized.failure_code,
        failure=audit_failure,
    )


def test_invalid_ai_configuration_uses_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(monkeypatch, operator=True)
    update, message = _make_update()
    normalized, _, _, _ = _prepare_normalized_flow(monkeypatch)
    audit = Mock()

    def fail_ai_configuration() -> None:
        raise AIConfigurationError("Local AI configuration is invalid.")

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        fail_ai_configuration,
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        audit,
    )

    asyncio.run(explain.explain_handler(update, object()))

    message.progress.edit_text.assert_awaited_once_with(
        explain._fallback_message(normalized),
        link_preview_options=(explain.DISABLED_LOG_LINK_PREVIEW),
    )
    assert audit.call_args_list[-1] == call(
        user_id=_OPERATOR_USER_ID,
        task=AIAuditTask.EXPLAIN_FAILURE,
        outcome=AIAuditOutcome.FAILED,
        job=normalized.job,
        failure_code=normalized.failure_code,
        failure=(AIAuditFailure.AI_CONFIGURATION_INVALID),
    )


def test_requested_audit_failure_blocks_ai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(monkeypatch, operator=True)
    update, message = _make_update()
    _prepare_normalized_flow(monkeypatch)
    ai_builder = Mock()

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        ai_builder,
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        Mock(side_effect=AIAuditError("AI audit failed.")),
    )

    asyncio.run(explain.explain_handler(update, object()))

    ai_builder.assert_not_called()
    message.progress.edit_text.assert_awaited_once_with(explain.AI_EXPLANATION_UNAVAILABLE_MESSAGE)


def test_success_audit_failure_hides_ai_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(monkeypatch, operator=True)
    update, message = _make_update()
    _prepare_normalized_flow(monkeypatch)

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        lambda: SimpleNamespace(explain_failure=AsyncMock(return_value=_explanation())),
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        Mock(
            side_effect=[
                None,
                AIAuditError("AI audit failed."),
            ]
        ),
    )

    asyncio.run(explain.explain_handler(update, object()))

    message.progress.edit_text.assert_awaited_once_with(explain.AI_EXPLANATION_UNAVAILABLE_MESSAGE)

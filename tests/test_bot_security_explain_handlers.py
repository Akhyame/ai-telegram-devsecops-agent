"""Offline security tests for Telegram /explain security."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call

import pytest

import bot.explain_handlers as explain
import bot.handlers as base_handlers
from agent.client import AIClientError, AIErrorKind
from agent.models import Confidence
from agent.security_models import (
    NormalizedSecurityScan,
    SecurityFindingSummary,
    SecurityScanDecision,
    SecurityScanExplanation,
    SecurityScanner,
    SecuritySeverity,
)
from bot.ai_audit import (
    AIAuditError,
    AIAuditFailure,
    AIAuditOutcome,
    AIAuditTask,
)
from bot.gitlab_client import GitLabClientError, GitLabErrorKind

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


def _make_update() -> tuple[SimpleNamespace, SimpleNamespace]:
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


def _context(
    *arguments: str,
) -> SimpleNamespace:
    return SimpleNamespace(
        args=list(arguments),
    )


def _scan() -> NormalizedSecurityScan:
    return NormalizedSecurityScan(
        decision=SecurityScanDecision.BLOCK,
        total_findings=6,
        blocking_findings=1,
        blocking_details=(
            SecurityFindingSummary(
                source=SecurityScanner.GITLEAKS,
                rule_id="gitlab-pat",
                severity=SecuritySeverity.HIGH,
            ),
        ),
        details_truncated=False,
    )


def _explanation() -> SecurityScanExplanation:
    return SecurityScanExplanation(
        summary="The Security Gate blocked the pipeline.",
        risk_explanation=("A high-severity credential pattern was detected."),
        safe_remediation=("Review and revoke the affected credential."),
        confidence=Confidence.HIGH,
    )


def _prepare_scan_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[NormalizedSecurityScan, AsyncMock]:
    scan = _scan()
    scan_request = AsyncMock(
        return_value=scan,
    )
    monkeypatch.setattr(
        explain,
        "_build_security_scan_result_client",
        lambda: SimpleNamespace(get_latest_security_scan=scan_request),
    )

    return scan, scan_request


def test_security_argument_returns_validated_scan_explanation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=True,
    )
    update, message = _make_update()
    scan, scan_request = _prepare_scan_flow(monkeypatch)
    explanation = _explanation()
    ai_request = AsyncMock(
        return_value=explanation,
    )
    audit = Mock()

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        lambda: SimpleNamespace(explain_security_scan=ai_request),
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        audit,
    )

    asyncio.run(
        explain.explain_handler(
            update,
            _context("security"),
        )
    )

    message.reply_text.assert_awaited_once_with(explain.AI_SECURITY_EXPLANATION_WAIT_MESSAGE)
    scan_request.assert_awaited_once_with()
    ai_request.assert_awaited_once_with(scan)
    audit.assert_has_calls(
        [
            call(
                user_id=_OPERATOR_USER_ID,
                task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
                outcome=AIAuditOutcome.REQUESTED,
            ),
            call(
                user_id=_OPERATOR_USER_ID,
                task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
                outcome=AIAuditOutcome.SUCCEEDED,
            ),
        ]
    )
    assert audit.call_count == 2

    expected = explain._security_explanation_message(
        scan,
        explanation,
    )
    message.progress.edit_text.assert_awaited_once_with(
        expected,
        link_preview_options=(explain.DISABLED_LOG_LINK_PREVIEW),
    )


def test_invalid_argument_is_rejected_without_external_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=True,
    )
    update, message = _make_update()
    security_builder = Mock()
    ai_builder = Mock()

    monkeypatch.setattr(
        explain,
        "_build_security_scan_result_client",
        security_builder,
    )
    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        ai_builder,
    )

    asyncio.run(
        explain.explain_handler(
            update,
            _context("security", "extra"),
        )
    )

    message.reply_text.assert_awaited_once_with(explain.AI_EXPLANATION_USAGE_MESSAGE)
    security_builder.assert_not_called()
    ai_builder.assert_not_called()


def test_viewer_cannot_request_security_explanation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=False,
    )
    update, _message = _make_update()
    security_builder = Mock()

    monkeypatch.setattr(
        explain,
        "_build_security_scan_result_client",
        security_builder,
    )

    asyncio.run(
        explain.explain_handler(
            update,
            _context("security"),
        )
    )

    security_builder.assert_not_called()


def test_gitlab_failure_returns_generic_message_and_never_calls_ai(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=True,
    )
    update, message = _make_update()
    scan_request = AsyncMock(
        side_effect=GitLabClientError(GitLabErrorKind.NETWORK),
    )
    ai_builder = Mock()
    audit = Mock()

    monkeypatch.setattr(
        explain,
        "_build_security_scan_result_client",
        lambda: SimpleNamespace(get_latest_security_scan=scan_request),
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

    asyncio.run(
        explain.explain_handler(
            update,
            _context("security"),
        )
    )

    scan_request.assert_awaited_once_with()
    ai_builder.assert_not_called()
    audit.assert_called_once_with(
        user_id=_OPERATOR_USER_ID,
        task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
        outcome=AIAuditOutcome.FAILED,
        failure=AIAuditFailure.GITLAB_UNAVAILABLE,
    )
    message.progress.edit_text.assert_awaited_once_with(explain.AI_EXPLANATION_UNAVAILABLE_MESSAGE)


def test_ai_failure_uses_normalized_metadata_only_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=True,
    )
    update, message = _make_update()
    scan, _scan_request = _prepare_scan_flow(monkeypatch)
    ai_request = AsyncMock(
        side_effect=AIClientError(AIErrorKind.TIMEOUT),
    )
    audit = Mock()

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        lambda: SimpleNamespace(explain_security_scan=ai_request),
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        audit,
    )

    asyncio.run(
        explain.explain_handler(
            update,
            _context("security"),
        )
    )

    ai_request.assert_awaited_once_with(scan)
    audit.assert_has_calls(
        [
            call(
                user_id=_OPERATOR_USER_ID,
                task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
                outcome=AIAuditOutcome.REQUESTED,
            ),
            call(
                user_id=_OPERATOR_USER_ID,
                task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
                outcome=AIAuditOutcome.FAILED,
                failure=AIAuditFailure.AI_TIMEOUT,
            ),
        ]
    )

    fallback = explain._security_fallback_message(scan)
    message.progress.edit_text.assert_awaited_once_with(
        fallback,
        link_preview_options=(explain.DISABLED_LOG_LINK_PREVIEW),
    )
    assert "gitlab-pat" not in fallback


def test_requested_audit_failure_blocks_ai_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=True,
    )
    update, message = _make_update()
    _scan, _scan_request = _prepare_scan_flow(monkeypatch)
    ai_builder = Mock()

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        ai_builder,
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        Mock(side_effect=AIAuditError),
    )

    asyncio.run(
        explain.explain_handler(
            update,
            _context("security"),
        )
    )

    ai_builder.assert_not_called()
    message.progress.edit_text.assert_awaited_once_with(explain.AI_EXPLANATION_UNAVAILABLE_MESSAGE)


def test_success_audit_failure_hides_ai_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=True,
    )
    update, message = _make_update()
    scan, _scan_request = _prepare_scan_flow(monkeypatch)
    ai_request = AsyncMock(
        return_value=_explanation(),
    )

    monkeypatch.setattr(
        explain,
        "_build_ai_client",
        lambda: SimpleNamespace(explain_security_scan=ai_request),
    )
    monkeypatch.setattr(
        explain,
        "emit_ai_audit",
        Mock(
            side_effect=(
                None,
                AIAuditError(),
            )
        ),
    )

    asyncio.run(
        explain.explain_handler(
            update,
            _context("security"),
        )
    )

    ai_request.assert_awaited_once_with(scan)
    message.progress.edit_text.assert_awaited_once_with(explain.AI_EXPLANATION_UNAVAILABLE_MESSAGE)


def test_standalone_security_command_uses_secure_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_role(
        monkeypatch,
        operator=True,
    )
    update, message = _make_update()
    security_flow = AsyncMock()
    monkeypatch.setattr(
        explain,
        "_explain_security_scan",
        security_flow,
    )

    asyncio.run(
        explain.explain_security_handler(
            update,
            _context(),
        )
    )

    security_flow.assert_awaited_once_with(
        message=message,
        user_id=_OPERATOR_USER_ID,
    )

"""Tests for metadata-only AI security scan audit events."""

import logging

import pytest

from agent.models import FailureCode, PipelineJob
from bot.ai_audit import (
    AI_AUDIT_LOG_MESSAGE,
    AIAuditError,
    AIAuditFailure,
    AIAuditOutcome,
    AIAuditTask,
    emit_ai_audit,
)

_USER_ID = 123456789


@pytest.mark.parametrize(
    "outcome",
    (
        AIAuditOutcome.REQUESTED,
        AIAuditOutcome.SUCCEEDED,
    ),
)
def test_security_scan_event_emits_only_controlled_metadata(
    outcome: AIAuditOutcome,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="bot.ai_audit"):
        emit_ai_audit(
            user_id=_USER_ID,
            task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
            outcome=outcome,
        )

    assert len(caplog.records) == 1
    record = caplog.records[0]

    assert record.getMessage() == AI_AUDIT_LOG_MESSAGE
    assert record.audit_event == "telegram_ai"
    assert record.audit_actor_user_id == _USER_ID
    assert record.audit_ai_task == "explain_security_scan"
    assert record.audit_outcome == outcome.value
    assert record.audit_job is None
    assert record.audit_failure_code is None
    assert record.audit_error_category is None

    for forbidden_field in (
        "audit_prompt",
        "audit_response",
        "audit_raw_log",
        "audit_scan",
        "audit_finding",
        "audit_rule_id",
        "audit_model_output",
        "audit_token",
    ):
        assert forbidden_field not in record.__dict__


def test_failed_security_scan_event_emits_controlled_category(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="bot.ai_audit"):
        emit_ai_audit(
            user_id=_USER_ID,
            task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
            outcome=AIAuditOutcome.FAILED,
            failure=AIAuditFailure.AI_TIMEOUT,
        )

    record = caplog.records[0]

    assert record.audit_ai_task == "explain_security_scan"
    assert record.audit_outcome == "failed"
    assert record.audit_job is None
    assert record.audit_failure_code is None
    assert record.audit_error_category == "ai_timeout"


@pytest.mark.parametrize(
    ("job", "failure_code"),
    (
        (
            PipelineJob.UNIT_TESTS,
            FailureCode.UNIT_TESTS_FAILED,
        ),
        (
            PipelineJob.SECURITY_GATE,
            FailureCode.SECURITY_GATE_BLOCKED,
        ),
    ),
)
def test_security_scan_task_rejects_pipeline_failure_context(
    job: PipelineJob,
    failure_code: FailureCode,
) -> None:
    with pytest.raises(
        AIAuditError,
        match=r"\AAI audit failed\.\Z",
    ):
        emit_ai_audit(
            user_id=_USER_ID,
            task=AIAuditTask.EXPLAIN_SECURITY_SCAN,
            outcome=AIAuditOutcome.REQUESTED,
            job=job,
            failure_code=failure_code,
        )

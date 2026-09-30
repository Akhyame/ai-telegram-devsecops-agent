"""Tests for content-free local AI audit events."""

import logging
from typing import Any

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
from bot.config import MAX_TELEGRAM_USER_ID

_USER_ID = 123456789


@pytest.mark.parametrize(
    "outcome",
    (
        AIAuditOutcome.REQUESTED,
        AIAuditOutcome.SUCCEEDED,
    ),
)
def test_context_event_emits_controlled_metadata(
    outcome: AIAuditOutcome,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="bot.ai_audit"):
        emit_ai_audit(
            user_id=_USER_ID,
            task=AIAuditTask.EXPLAIN_FAILURE,
            outcome=outcome,
            job=PipelineJob.UNIT_TESTS,
            failure_code=FailureCode.UNIT_TESTS_FAILED,
        )

    assert len(caplog.records) == 1
    record = caplog.records[0]

    assert record.getMessage() == AI_AUDIT_LOG_MESSAGE
    assert record.audit_event == "telegram_ai"
    assert record.audit_actor_user_id == _USER_ID
    assert record.audit_ai_task == "explain_failure"
    assert record.audit_outcome == outcome.value
    assert record.audit_job == "unit_tests"
    assert record.audit_failure_code == "unit_tests_failed"
    assert record.audit_error_category is None

    for forbidden_field in (
        "audit_prompt",
        "audit_response",
        "audit_raw_log",
        "audit_model_output",
        "audit_token",
    ):
        assert forbidden_field not in record.__dict__


@pytest.mark.parametrize(
    ("job", "failure_code"),
    (
        (None, None),
        (
            PipelineJob.DEPENDENCY_SCAN,
            FailureCode.DEPENDENCY_DOWNLOAD_TIMEOUT,
        ),
    ),
)
def test_failed_event_accepts_optional_normalized_context(
    job: PipelineJob | None,
    failure_code: FailureCode | None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.INFO, logger="bot.ai_audit"):
        emit_ai_audit(
            user_id=_USER_ID,
            task=AIAuditTask.EXPLAIN_FAILURE,
            outcome=AIAuditOutcome.FAILED,
            job=job,
            failure_code=failure_code,
            failure=AIAuditFailure.AI_TIMEOUT,
        )

    record = caplog.records[0]

    assert record.audit_outcome == "failed"
    assert record.audit_job == (None if job is None else job.value)
    assert record.audit_failure_code == (None if failure_code is None else failure_code.value)
    assert record.audit_error_category == "ai_timeout"


@pytest.mark.parametrize(
    "overrides",
    (
        {"user_id": None},
        {"user_id": True},
        {"user_id": 0},
        {"user_id": MAX_TELEGRAM_USER_ID + 1},
        {"task": "explain_failure"},
        {"outcome": "requested"},
        {"job": "unit_tests"},
        {"failure_code": "unit_tests_failed"},
        {"failure": "ai_timeout"},
        {"job": None},
        {"failure_code": None},
        {"failure": AIAuditFailure.AI_TIMEOUT},
        {
            "outcome": AIAuditOutcome.FAILED,
            "failure": None,
        },
    ),
)
def test_invalid_audit_events_fail_closed(
    overrides: dict[str, Any],
) -> None:
    event: dict[str, Any] = {
        "user_id": _USER_ID,
        "task": AIAuditTask.EXPLAIN_FAILURE,
        "outcome": AIAuditOutcome.REQUESTED,
        "job": PipelineJob.UNIT_TESTS,
        "failure_code": FailureCode.UNIT_TESTS_FAILED,
        "failure": None,
    }
    event.update(overrides)

    with pytest.raises(
        AIAuditError,
        match=r"\AAI audit failed\.\Z",
    ):
        emit_ai_audit(**event)


@pytest.mark.parametrize(
    ("job", "failure_code"),
    (
        (PipelineJob.UNIT_TESTS, None),
        (None, FailureCode.UNIT_TESTS_FAILED),
    ),
)
def test_partial_normalized_context_is_rejected(
    job: PipelineJob | None,
    failure_code: FailureCode | None,
) -> None:
    with pytest.raises(
        AIAuditError,
        match=r"\AAI audit failed\.\Z",
    ):
        emit_ai_audit(
            user_id=_USER_ID,
            task=AIAuditTask.EXPLAIN_FAILURE,
            outcome=AIAuditOutcome.FAILED,
            job=job,
            failure_code=failure_code,
            failure=AIAuditFailure.NORMALIZATION_FAILED,
        )

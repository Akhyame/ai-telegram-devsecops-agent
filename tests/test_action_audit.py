"""Tests for controlled Telegram action audit events."""

import logging

import pytest

from bot.action_audit import (
    ACTION_AUDIT_LOG_MESSAGE,
    ActionAuditError,
    ActionAuditOutcome,
    emit_action_audit,
)
from bot.action_confirmation import (
    ActionKind,
    ActionTarget,
)
from bot.config import MAX_TELEGRAM_USER_ID
from deployment.models import DeploymentEnvironment

_USER_ID = 101
_PROJECT_ID = 123456
_REF = "main"


def _target(
    action: ActionKind,
) -> ActionTarget:
    pipeline_id = (
        987654
        if action
        in {
            ActionKind.CANCEL_PIPELINE,
            ActionKind.RETRY_PIPELINE,
        }
        else None
    )

    return ActionTarget(
        project_id=_PROJECT_ID,
        ref=_REF,
        pipeline_id=pipeline_id,
    )


@pytest.mark.parametrize(
    "action",
    tuple(ActionKind),
)
@pytest.mark.parametrize(
    "outcome",
    tuple(ActionAuditOutcome),
)
def test_all_controlled_action_events_are_structured(
    caplog: pytest.LogCaptureFixture,
    action: ActionKind,
    outcome: ActionAuditOutcome,
) -> None:
    caplog.set_level(
        logging.INFO,
        logger="bot.action_audit",
    )
    target = _target(action)

    if action is ActionKind.DEPLOY:
        target = ActionTarget(
            project_id=target.project_id,
            ref=target.ref,
            pipeline_id=target.pipeline_id,
            environment=DeploymentEnvironment.STAGING,
        )

    emit_action_audit(
        user_id=_USER_ID,
        action=action,
        outcome=outcome,
        target=target,
    )

    record = caplog.records[-1]
    assert record.getMessage() == ACTION_AUDIT_LOG_MESSAGE
    assert record.audit_event == "telegram_action"
    assert record.audit_actor_user_id == _USER_ID
    assert record.audit_action == action.value
    assert record.audit_outcome == outcome.value
    assert record.audit_project_id == _PROJECT_ID
    assert record.audit_ref == _REF
    assert record.audit_pipeline_id == target.pipeline_id


@pytest.mark.parametrize(
    ("user_id", "action", "outcome", "target"),
    (
        (
            True,
            ActionKind.RUN_PIPELINE,
            ActionAuditOutcome.REQUESTED,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
        (
            0,
            ActionKind.RUN_PIPELINE,
            ActionAuditOutcome.REQUESTED,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
        (
            MAX_TELEGRAM_USER_ID + 1,
            ActionKind.RUN_PIPELINE,
            ActionAuditOutcome.REQUESTED,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
        (
            _USER_ID,
            "run_pipeline",
            ActionAuditOutcome.REQUESTED,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
        (
            _USER_ID,
            ActionKind.RUN_PIPELINE,
            "requested",
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
        (
            _USER_ID,
            ActionKind.CANCEL_PIPELINE,
            ActionAuditOutcome.REQUESTED,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
            ),
        ),
        (
            _USER_ID,
            ActionKind.RUN_PIPELINE,
            ActionAuditOutcome.REQUESTED,
            ActionTarget(
                project_id=_PROJECT_ID,
                ref=_REF,
                pipeline_id=987654,
            ),
        ),
    ),
)
def test_invalid_audit_events_fail_closed_without_logging(
    caplog: pytest.LogCaptureFixture,
    user_id: object,
    action: object,
    outcome: object,
    target: ActionTarget,
) -> None:
    caplog.set_level(
        logging.INFO,
        logger="bot.action_audit",
    )

    with pytest.raises(
        ActionAuditError,
        match=r"\AAction audit failed\.\Z",
    ):
        emit_action_audit(
            user_id=user_id,
            action=action,
            outcome=outcome,
            target=target,
        )

    assert not caplog.records


def test_audit_record_has_no_confirmation_or_credential_field(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_marker = "DO-NOT-LEAK-CONFIRMATION-OR-TOKEN"
    caplog.set_level(
        logging.INFO,
        logger="bot.action_audit",
    )

    emit_action_audit(
        user_id=_USER_ID,
        action=ActionKind.RUN_PIPELINE,
        outcome=ActionAuditOutcome.REQUESTED,
        target=_target(ActionKind.RUN_PIPELINE),
    )

    record = caplog.records[-1]
    assert sensitive_marker not in caplog.text
    assert not hasattr(record, "token")
    assert not hasattr(record, "confirmation_token")
    assert not hasattr(record, "credential")

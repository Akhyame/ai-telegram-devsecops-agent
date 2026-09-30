"""Tests for normalized pipeline events and replay protection."""

import pytest

from sample_app.webhook_events import (
    MAX_PIPELINE_IDENTIFIER,
    MAX_PIPELINE_REF_CHARACTERS,
    MAX_REPLAY_ENTRIES,
    PipelineEventStatus,
    WebhookReplayGuard,
    normalize_pipeline_event,
)
from sample_app.webhook_security import WebhookRequestError

_PROJECT_ID = 123456
_SHA = "a" * 40


def _payload(**overrides: object) -> dict[str, object]:
    attributes: dict[str, object] = {
        "id": 987654,
        "status": "success",
        "ref": "main",
        "sha": _SHA,
    }
    attributes.update(overrides)

    return {
        "object_kind": "pipeline",
        "project": {"id": _PROJECT_ID},
        "object_attributes": attributes,
        "user": {"email": "do-not-copy@example.invalid"},
        "variables": [{"value": "do-not-copy"}],
    }


def test_event_security_boundaries_are_fixed() -> None:
    assert MAX_REPLAY_ENTRIES == 1_024
    assert MAX_PIPELINE_IDENTIFIER == (2**63) - 1
    assert MAX_PIPELINE_REF_CHARACTERS == 255


def test_valid_event_is_minimized() -> None:
    event = normalize_pipeline_event(_payload(), project_id=_PROJECT_ID)

    assert event.pipeline_id == 987654
    assert event.status is PipelineEventStatus.SUCCESS
    assert event.ref == "main"
    assert event.sha == _SHA
    assert "do-not-copy" not in repr(event)
    assert "example.invalid" not in repr(event)


@pytest.mark.parametrize("status", tuple(item.value for item in PipelineEventStatus))
def test_documented_statuses_are_accepted(status: str) -> None:
    event = normalize_pipeline_event(
        _payload(status=status),
        project_id=_PROJECT_ID,
    )

    assert event.status.value == status


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("id", True),
        ("id", 0),
        ("id", MAX_PIPELINE_IDENTIFIER + 1),
        ("status", None),
        ("status", "unexpected"),
        ("ref", ""),
        ("ref", "../main"),
        ("ref", "feature//unsafe"),
        ("ref", "A" * (MAX_PIPELINE_REF_CHARACTERS + 1)),
        ("sha", "A" * 40),
        ("sha", "a" * 39),
        ("sha", "a" * 65),
    ),
)
def test_invalid_pipeline_fields_are_rejected(
    field: str,
    invalid_value: object,
) -> None:
    with pytest.raises(WebhookRequestError, match=r"\AWebhook request is invalid\.\Z"):
        normalize_pipeline_event(
            _payload(**{field: invalid_value}),
            project_id=_PROJECT_ID,
        )


@pytest.mark.parametrize("invalid_project_id", (True, 0, 654321, "123456"))
def test_wrong_project_is_rejected(invalid_project_id: object) -> None:
    payload = _payload()
    payload["project"] = {"id": invalid_project_id}

    with pytest.raises(WebhookRequestError):
        normalize_pipeline_event(payload, project_id=_PROJECT_ID)


def test_duplicate_message_is_rejected() -> None:
    guard = WebhookReplayGuard()

    assert guard.claim("message-1", current_timestamp=1_000)
    assert not guard.claim("message-1", current_timestamp=1_001)


def test_identifier_is_reaccepted_after_expiry() -> None:
    guard = WebhookReplayGuard(ttl_seconds=300)

    assert guard.claim("message-1", current_timestamp=1_000)
    assert guard.claim("message-1", current_timestamp=1_300)


def test_released_identifier_can_be_claimed_again() -> None:
    guard = WebhookReplayGuard()

    assert guard.claim("message-1", current_timestamp=1_000)
    guard.release("message-1")
    guard.release("unknown")
    assert guard.claim("message-1", current_timestamp=1_001)


def test_replay_cache_is_bounded() -> None:
    guard = WebhookReplayGuard(maximum_entries=2, ttl_seconds=300)

    assert guard.claim("oldest", current_timestamp=1_000)
    assert guard.claim("newer", current_timestamp=1_001)
    assert guard.claim("newest", current_timestamp=1_002)
    assert guard.claim("oldest", current_timestamp=1_003)


@pytest.mark.parametrize(
    ("maximum_entries", "ttl_seconds"),
    ((0, 300), (1, 0), (-1, 300), (1, -1)),
)
def test_invalid_guard_limits_are_rejected(
    maximum_entries: int,
    ttl_seconds: int,
) -> None:
    with pytest.raises(ValueError, match=r"\AReplay guard limits are invalid\.\Z"):
        WebhookReplayGuard(
            maximum_entries=maximum_entries,
            ttl_seconds=ttl_seconds,
        )

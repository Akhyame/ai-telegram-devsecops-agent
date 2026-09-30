"""Validated pipeline events and bounded replay protection."""

import re
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Any

from sample_app.webhook_config import MAX_WEBHOOK_TIMESTAMP_AGE_SECONDS
from sample_app.webhook_security import WebhookRequestError

MAX_REPLAY_ENTRIES = 1_024
MAX_PIPELINE_IDENTIFIER = (2**63) - 1
MAX_PIPELINE_REF_CHARACTERS = 255

_SAFE_REF_PATTERN = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9])?\Z")
_SHA_PATTERN = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class PipelineEventStatus(StrEnum):
    """Accepted GitLab pipeline states."""

    CREATED = "created"
    WAITING_FOR_RESOURCE = "waiting_for_resource"
    PREPARING = "preparing"
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELED = "canceled"
    SKIPPED = "skipped"
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    WAITING_FOR_CALLBACK = "waiting_for_callback"
    CANCELING = "canceling"


@dataclass(frozen=True, slots=True)
class PipelineWebhookEvent:
    """Minimal trusted pipeline event used by notifications."""

    pipeline_id: int
    status: PipelineEventStatus
    ref: str
    sha: str


def _invalid_request() -> WebhookRequestError:
    return WebhookRequestError("Webhook request is invalid.")


def _validated_ref(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_PIPELINE_REF_CHARACTERS
        or _SAFE_REF_PATTERN.fullmatch(value) is None
        or ".." in value
        or "//" in value
        or "@{" in value
        or value.endswith(".lock")
    ):
        raise _invalid_request()

    return value


def normalize_pipeline_event(
    payload: dict[str, Any],
    *,
    project_id: int,
) -> PipelineWebhookEvent:
    """Extract only validated non-sensitive pipeline fields."""

    if payload.get("object_kind") != "pipeline":
        raise _invalid_request()

    project = payload.get("project")

    if not isinstance(project, dict):
        raise _invalid_request()

    payload_project_id = project.get("id")

    if (
        not isinstance(payload_project_id, int)
        or isinstance(payload_project_id, bool)
        or payload_project_id <= 0
        or payload_project_id != project_id
    ):
        raise _invalid_request()

    attributes = payload.get("object_attributes")

    if not isinstance(attributes, dict):
        raise _invalid_request()

    pipeline_id = attributes.get("id")

    if (
        not isinstance(pipeline_id, int)
        or isinstance(pipeline_id, bool)
        or not 1 <= pipeline_id <= MAX_PIPELINE_IDENTIFIER
    ):
        raise _invalid_request()

    raw_status = attributes.get("status")

    if not isinstance(raw_status, str):
        raise _invalid_request()

    try:
        pipeline_status = PipelineEventStatus(raw_status)
    except ValueError as exc:
        raise _invalid_request() from exc

    sha = attributes.get("sha")

    if not isinstance(sha, str) or _SHA_PATTERN.fullmatch(sha) is None:
        raise _invalid_request()

    return PipelineWebhookEvent(
        pipeline_id=pipeline_id,
        status=pipeline_status,
        ref=_validated_ref(attributes.get("ref")),
        sha=sha,
    )


class WebhookReplayGuard:
    """Process-local bounded cache for authenticated message IDs."""

    def __init__(
        self,
        *,
        maximum_entries: int = MAX_REPLAY_ENTRIES,
        ttl_seconds: int = MAX_WEBHOOK_TIMESTAMP_AGE_SECONDS,
    ) -> None:
        if maximum_entries <= 0 or ttl_seconds <= 0:
            raise ValueError("Replay guard limits are invalid.")

        self._maximum_entries = maximum_entries
        self._ttl_seconds = ttl_seconds
        self._entries: dict[str, int] = {}
        self._lock = Lock()

    def claim(self, message_id: str, *, current_timestamp: int) -> bool:
        """Claim a verified message ID once inside the replay window."""

        with self._lock:
            expired = [
                identifier
                for identifier, expires_at in self._entries.items()
                if expires_at <= current_timestamp
            ]

            for identifier in expired:
                del self._entries[identifier]

            if message_id in self._entries:
                return False

            if len(self._entries) >= self._maximum_entries:
                oldest = min(self._entries, key=self._entries.__getitem__)
                del self._entries[oldest]

            self._entries[message_id] = current_timestamp + self._ttl_seconds
            return True

    def release(self, message_id: str) -> None:
        """Release a claim when notification configuration is unavailable."""

        with self._lock:
            self._entries.pop(message_id, None)

    def clear(self) -> None:
        """Clear state for deterministic tests."""

        with self._lock:
            self._entries.clear()


webhook_replay_guard = WebhookReplayGuard()

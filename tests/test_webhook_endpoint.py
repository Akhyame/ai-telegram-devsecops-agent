"""Offline tests for the authenticated GitLab webhook endpoint."""

import base64
import hashlib
import hmac
import json
from collections.abc import Iterator
from pathlib import Path
from time import time
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from sample_app.main import app
from sample_app.webhook_config import (
    GITLAB_WEBHOOK_INSTANCE,
    MAX_WEBHOOK_BODY_BYTES,
    get_webhook_settings,
)
from sample_app.webhook_endpoint import (
    INVALID_WEBHOOK_MESSAGE,
    RATE_LIMITED_MESSAGE,
    SERVICE_UNAVAILABLE_MESSAGE,
    WEBHOOK_PATH,
    WEBHOOK_RATE_LIMIT_MAX_REQUESTS,
    webhook_rate_limiter,
)
from sample_app.webhook_events import webhook_replay_guard
from sample_app.webhook_notifications import (
    PipelineNotificationConfigurationError,
)

_PROJECT_ID = 123456
_KEY = b"W" * 32


@pytest.fixture(autouse=True)
def _isolate_webhook_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[AsyncMock]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(
        "GITLAB_PROJECT_ID",
        raising=False,
    )
    monkeypatch.delenv(
        "GITLAB_WEBHOOK_SIGNING_TOKEN",
        raising=False,
    )
    get_webhook_settings.cache_clear()
    webhook_replay_guard.clear()
    webhook_rate_limiter.clear()

    with patch(
        "sample_app.webhook_endpoint.notify_pipeline_event",
        new_callable=AsyncMock,
    ) as notification:
        yield notification

    webhook_replay_guard.clear()
    webhook_rate_limiter.clear()
    get_webhook_settings.cache_clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


def _configure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "whsec_" + base64.b64encode(_KEY).decode("ascii")
    monkeypatch.setenv(
        "GITLAB_PROJECT_ID",
        str(_PROJECT_ID),
    )
    monkeypatch.setenv(
        "GITLAB_WEBHOOK_SIGNING_TOKEN",
        token,
    )


def _payload(
    *,
    project_id: object = _PROJECT_ID,
    object_kind: object = "pipeline",
) -> bytes:
    return json.dumps(
        {
            "object_kind": object_kind,
            "project": {
                "id": project_id,
            },
            "object_attributes": {
                "id": 987654,
                "status": "success",
                "ref": "main",
                "sha": "a" * 40,
            },
        },
        separators=(",", ":"),
    ).encode()


def _headers(
    body: bytes,
    *,
    timestamp: str | None = None,
    message_id: str = "message-123",
) -> dict[str, str]:
    timestamp = str(int(time())) if timestamp is None else timestamp
    signed_message = b".".join(
        (
            message_id.encode("ascii"),
            timestamp.encode("ascii"),
            body,
        )
    )
    digest = hmac.new(
        _KEY,
        signed_message,
        hashlib.sha256,
    ).digest()
    signature = "v1," + base64.b64encode(digest).decode("ascii")

    return {
        "Content-Type": "application/json",
        "X-Gitlab-Event": "Pipeline Hook",
        "X-Gitlab-Instance": (GITLAB_WEBHOOK_INSTANCE),
        "webhook-id": message_id,
        "webhook-timestamp": timestamp,
        "webhook-signature": signature,
    }


def test_valid_pipeline_hook_is_accepted(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    body = _payload()

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(body),
    )

    assert response.status_code == 202
    assert response.content == b""


@pytest.mark.parametrize(
    "missing_header",
    (
        "X-Gitlab-Event",
        "X-Gitlab-Instance",
        "webhook-id",
        "webhook-timestamp",
        "webhook-signature",
    ),
)
def test_required_headers_are_enforced(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    missing_header: str,
) -> None:
    _configure(monkeypatch)
    body = _payload()
    headers = _headers(body)
    del headers[missing_header]

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=headers,
    )

    assert response.status_code == 400
    assert response.json() == {
        "detail": INVALID_WEBHOOK_MESSAGE,
    }


@pytest.mark.parametrize(
    ("header", "invalid_value"),
    (
        (
            "Content-Type",
            "text/plain",
        ),
        (
            "X-Gitlab-Event",
            "Push Hook",
        ),
        (
            "X-Gitlab-Instance",
            "https://example.invalid",
        ),
    ),
)
def test_untrusted_delivery_metadata_is_rejected(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    header: str,
    invalid_value: str,
) -> None:
    _configure(monkeypatch)
    body = _payload()
    headers = _headers(body)
    headers[header] = invalid_value

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=headers,
    )

    assert response.status_code == 400


def test_invalid_signature_is_rejected(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    body = _payload()
    headers = _headers(body)
    headers["webhook-signature"] = "v1,invalid"

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=headers,
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "age",
    (
        -301,
        301,
    ),
)
def test_stale_or_future_delivery_is_rejected(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    age: int,
) -> None:
    _configure(monkeypatch)
    body = _payload()
    timestamp = str(int(time()) + age)

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(
            body,
            timestamp=timestamp,
        ),
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    ("project_id", "object_kind"),
    (
        (
            654321,
            "pipeline",
        ),
        (
            True,
            "pipeline",
        ),
        (
            _PROJECT_ID,
            "push",
        ),
    ),
)
def test_wrong_project_or_event_payload_is_rejected(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    project_id: object,
    object_kind: object,
) -> None:
    _configure(monkeypatch)
    body = _payload(
        project_id=project_id,
        object_kind=object_kind,
    )

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(body),
    )

    assert response.status_code == 400


@pytest.mark.parametrize(
    "invalid_body",
    (
        b"",
        b"null",
        b"[]",
        b"{invalid-json}",
        b'{"object_kind":"pipeline","object_kind":"pipeline"}',
        b"\xff",
    ),
)
def test_invalid_json_is_rejected(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    invalid_body: bytes,
) -> None:
    _configure(monkeypatch)

    response = client.post(
        WEBHOOK_PATH,
        content=invalid_body,
        headers=_headers(invalid_body),
    )

    assert response.status_code == 400


def test_oversized_body_is_rejected(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    body = b"A" * (MAX_WEBHOOK_BODY_BYTES + 1)

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(body),
    )

    assert response.status_code == 400


def test_missing_configuration_is_controlled(
    client: TestClient,
) -> None:
    body = _payload()

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(body),
    )

    assert response.status_code == 503
    assert response.json() == {
        "detail": SERVICE_UNAVAILABLE_MESSAGE,
    }


def test_endpoint_is_hidden_from_openapi(
    client: TestClient,
) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert WEBHOOK_PATH not in response.json()["paths"]


def test_valid_event_is_sent_to_notification_layer(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    _isolate_webhook_environment: AsyncMock,
) -> None:
    _configure(monkeypatch)
    body = _payload()

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(body),
    )

    assert response.status_code == 202
    _isolate_webhook_environment.assert_awaited_once()
    event = _isolate_webhook_environment.await_args.args[0]
    assert event.pipeline_id == 987654
    assert event.status.value == "success"
    assert event.ref == "main"
    assert event.sha == "a" * 40


def test_duplicate_delivery_is_not_notified_twice(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    _isolate_webhook_environment: AsyncMock,
) -> None:
    _configure(monkeypatch)
    body = _payload()
    headers = _headers(body)

    first = client.post(WEBHOOK_PATH, content=body, headers=headers)
    second = client.post(WEBHOOK_PATH, content=body, headers=headers)

    assert first.status_code == 202
    assert second.status_code == 202
    _isolate_webhook_environment.assert_awaited_once()


def test_notification_configuration_failure_is_retryable(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    _isolate_webhook_environment: AsyncMock,
) -> None:
    _configure(monkeypatch)
    body = _payload()
    headers = _headers(body)
    _isolate_webhook_environment.side_effect = (
        PipelineNotificationConfigurationError("DO-NOT-PROPAGATE"),
        None,
    )

    first = client.post(WEBHOOK_PATH, content=body, headers=headers)
    second = client.post(WEBHOOK_PATH, content=body, headers=headers)

    assert first.status_code == 503
    assert first.json() == {
        "detail": SERVICE_UNAVAILABLE_MESSAGE,
    }
    assert "DO-NOT-PROPAGATE" not in first.text
    assert second.status_code == 202
    assert _isolate_webhook_environment.await_count == 2


def test_authenticated_webhook_is_rate_limited(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    body = _payload()

    for index in range(WEBHOOK_RATE_LIMIT_MAX_REQUESTS):
        response = client.post(
            WEBHOOK_PATH,
            content=body,
            headers=_headers(
                body,
                message_id=f"rate-{index}",
            ),
        )

        assert response.status_code == 202

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(
            body,
            message_id="rate-excess",
        ),
    )

    assert response.status_code == 429
    assert response.json() == {
        "detail": RATE_LIMITED_MESSAGE,
    }


def test_invalid_webhook_authentication_does_not_consume_rate_limit(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    body = _payload()

    for index in range(WEBHOOK_RATE_LIMIT_MAX_REQUESTS + 2):
        headers = _headers(
            body,
            message_id=f"invalid-rate-{index}",
        )
        headers["webhook-signature"] = "v1,invalid"

        response = client.post(
            WEBHOOK_PATH,
            content=body,
            headers=headers,
        )

        assert response.status_code == 400

    response = client.post(
        WEBHOOK_PATH,
        content=body,
        headers=_headers(
            body,
            message_id="valid-after-invalid",
        ),
    )

    assert response.status_code == 202

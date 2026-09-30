"""Offline tests for GitLab webhook authentication."""

import asyncio
import base64
import hashlib
import hmac

import pytest
from pydantic import SecretStr

from sample_app.webhook_config import (
    MAX_WEBHOOK_BODY_BYTES,
    GitLabWebhookSettings,
)
from sample_app.webhook_security import (
    MAX_WEBHOOK_ID_CHARACTERS,
    MAX_WEBHOOK_SIGNATURE_CHARACTERS,
    MAX_WEBHOOK_SIGNATURES,
    WebhookRequestError,
    read_bounded_webhook_body,
    verify_webhook_request,
)

_PROJECT_ID = 123456
_CURRENT_TIMESTAMP = 1_800_000_000
_MESSAGE_ID = "message-id-123"
_BODY = b'{"object_kind":"pipeline"}'


def _settings() -> GitLabWebhookSettings:
    key = b"K" * 32
    token = "whsec_" + base64.b64encode(key).decode("ascii")

    return GitLabWebhookSettings(
        GITLAB_PROJECT_ID=_PROJECT_ID,
        GITLAB_WEBHOOK_SIGNING_TOKEN=(SecretStr(token)),
    )


def _signature(
    *,
    message_id: str = _MESSAGE_ID,
    timestamp: str = str(_CURRENT_TIMESTAMP),
    body: bytes = _BODY,
) -> str:
    key = b"K" * 32
    message = b".".join(
        (
            message_id.encode("ascii"),
            timestamp.encode("ascii"),
            body,
        )
    )
    digest = hmac.new(
        key,
        message,
        hashlib.sha256,
    ).digest()

    return "v1," + base64.b64encode(digest).decode("ascii")


def _verify(
    *,
    message_id: str = _MESSAGE_ID,
    timestamp: str = str(_CURRENT_TIMESTAMP),
    body: bytes = _BODY,
    signatures: str | None = None,
    current_timestamp: int = (_CURRENT_TIMESTAMP),
) -> None:
    verify_webhook_request(
        settings=_settings(),
        message_id=message_id,
        timestamp=timestamp,
        received_signatures=(
            _signature(
                message_id=message_id,
                timestamp=timestamp,
                body=body,
            )
            if signatures is None
            else signatures
        ),
        body=body,
        current_timestamp=current_timestamp,
    )


def test_security_boundaries_are_fixed() -> None:
    assert MAX_WEBHOOK_ID_CHARACTERS == 200
    assert MAX_WEBHOOK_SIGNATURE_CHARACTERS == 2_048
    assert MAX_WEBHOOK_SIGNATURES == 5


def test_valid_signature_is_accepted() -> None:
    _verify()


def test_matching_signature_in_rotation_list_is_accepted() -> None:
    _verify(
        signatures=("v1,invalid " + _signature()),
    )


@pytest.mark.parametrize(
    "invalid_message_id",
    (
        "",
        "unsafe\nidentifier",
        "A" * (MAX_WEBHOOK_ID_CHARACTERS + 1),
        "é",
    ),
)
def test_invalid_message_id_is_rejected(
    invalid_message_id: str,
) -> None:
    with pytest.raises(
        WebhookRequestError,
        match=(
            r"\AWebhook request "
            r"is invalid\.\Z"
        ),
    ):
        _verify(
            message_id=invalid_message_id,
            signatures="v1,invalid",
        )


@pytest.mark.parametrize(
    "invalid_timestamp",
    (
        "",
        "-1",
        "1.5",
        "not-a-timestamp",
        "1" * 21,
    ),
)
def test_invalid_timestamp_is_rejected(
    invalid_timestamp: str,
) -> None:
    with pytest.raises(
        WebhookRequestError,
    ):
        _verify(
            timestamp=invalid_timestamp,
            signatures="v1,invalid",
        )


@pytest.mark.parametrize(
    "request_timestamp",
    (
        (_CURRENT_TIMESTAMP - 301),
        (_CURRENT_TIMESTAMP + 301),
    ),
)
def test_timestamp_outside_window_is_rejected(
    request_timestamp: int,
) -> None:
    with pytest.raises(
        WebhookRequestError,
    ):
        _verify(
            timestamp=str(request_timestamp),
        )


def test_timestamp_at_window_boundary_is_accepted() -> None:
    timestamp = str(_CURRENT_TIMESTAMP - 300)

    _verify(timestamp=timestamp)


@pytest.mark.parametrize(
    "tampered_body",
    (
        b'{"object_kind":"job"}',
        b"",
    ),
)
def test_tampered_body_is_rejected(
    tampered_body: bytes,
) -> None:
    with pytest.raises(
        WebhookRequestError,
    ):
        _verify(
            body=tampered_body,
            signatures=_signature(),
        )


@pytest.mark.parametrize(
    "invalid_signatures",
    (
        "",
        "v1,invalid",
        ("v1,invalid " * (MAX_WEBHOOK_SIGNATURES + 1)).strip(),
        "A" * (MAX_WEBHOOK_SIGNATURE_CHARACTERS + 1),
    ),
)
def test_invalid_signatures_are_rejected(
    invalid_signatures: str,
) -> None:
    with pytest.raises(
        WebhookRequestError,
        match=(
            r"\AWebhook request "
            r"is invalid\.\Z"
        ),
    ):
        _verify(
            signatures=invalid_signatures,
        )


def test_error_never_contains_signing_material() -> None:
    settings = _settings()
    token = settings.signing_token.get_secret_value()

    with pytest.raises(
        WebhookRequestError,
    ) as error:
        _verify(
            signatures="v1,invalid",
        )

    assert token not in str(error.value)
    assert _BODY.decode() not in str(error.value)
    assert _MESSAGE_ID not in str(error.value)


def _request(
    chunks: tuple[bytes, ...],
    *,
    content_length: str | None,
) -> object:
    messages = [
        {
            "type": "http.request",
            "body": chunk,
            "more_body": (index < len(chunks) - 1),
        }
        for index, chunk in enumerate(chunks)
    ]

    if not messages:
        messages.append(
            {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }
        )

    async def receive() -> dict[str, object]:
        return messages.pop(0)

    headers = []

    if content_length is not None:
        headers.append(
            (
                b"content-length",
                content_length.encode("ascii"),
            )
        )

    from starlette.requests import Request

    return Request(
        {
            "type": "http",
            "asgi": {
                "version": "3.0",
            },
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/webhooks/gitlab",
            "raw_path": b"/webhooks/gitlab",
            "query_string": b"",
            "headers": headers,
            "client": (
                "127.0.0.1",
                12345,
            ),
            "server": (
                "testserver",
                443,
            ),
        },
        receive,
    )


def _read_body(
    chunks: tuple[bytes, ...],
    *,
    content_length: str | None,
) -> bytes:
    request = _request(
        chunks,
        content_length=content_length,
    )

    return asyncio.run(read_bounded_webhook_body(request))


def test_bounded_reader_accepts_valid_body() -> None:
    body = _read_body(
        (
            b'{"object_',
            b'kind":"pipeline"}',
        ),
        content_length="26",
    )

    assert body == _BODY


def test_bounded_reader_accepts_missing_content_length() -> None:
    body = _read_body(
        (_BODY,),
        content_length=None,
    )

    assert body == _BODY


def test_bounded_reader_accepts_exact_byte_limit() -> None:
    body = b"A" * MAX_WEBHOOK_BODY_BYTES

    assert (
        _read_body(
            (body,),
            content_length=str(len(body)),
        )
        == body
    )


@pytest.mark.parametrize(
    "invalid_length",
    (
        "",
        "-1",
        "1.5",
        "invalid",
        "1" * 21,
    ),
)
def test_invalid_content_length_is_rejected(
    invalid_length: str,
) -> None:
    with pytest.raises(
        WebhookRequestError,
    ):
        _read_body(
            (_BODY,),
            content_length=invalid_length,
        )


def test_declared_oversized_body_is_rejected_before_reading() -> None:
    with pytest.raises(
        WebhookRequestError,
    ):
        _read_body(
            (_BODY,),
            content_length=str(MAX_WEBHOOK_BODY_BYTES + 1),
        )


def test_streamed_oversized_body_is_rejected() -> None:
    with pytest.raises(
        WebhookRequestError,
    ):
        _read_body(
            (
                b"A" * MAX_WEBHOOK_BODY_BYTES,
                b"B",
            ),
            content_length=None,
        )


def test_declared_and_actual_lengths_must_match() -> None:
    with pytest.raises(
        WebhookRequestError,
    ):
        _read_body(
            (_BODY,),
            content_length="1",
        )


def test_body_reader_error_contains_no_body() -> None:
    sensitive_body = b"DO-NOT-LEAK-WEBHOOK-BODY"

    with pytest.raises(
        WebhookRequestError,
        match=(
            r"\AWebhook request "
            r"is invalid\.\Z"
        ),
    ) as error:
        _read_body(
            (sensitive_body,),
            content_length="1",
        )

    assert sensitive_body.decode() not in str(error.value)

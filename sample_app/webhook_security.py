"""Authentication primitives for signed GitLab webhooks."""

import base64
import hashlib
import hmac

from starlette.requests import Request

from sample_app.webhook_config import (
    MAX_WEBHOOK_BODY_BYTES,
    MAX_WEBHOOK_TIMESTAMP_AGE_SECONDS,
    GitLabWebhookSettings,
)

MAX_WEBHOOK_ID_CHARACTERS = 200
MAX_WEBHOOK_SIGNATURE_CHARACTERS = 2_048
MAX_WEBHOOK_SIGNATURES = 5


class WebhookRequestError(RuntimeError):
    """Raised when an incoming webhook fails authentication."""


def _invalid_request() -> WebhookRequestError:
    return WebhookRequestError("Webhook request is invalid.")


def _valid_visible_ascii(
    value: str,
    *,
    maximum: int,
) -> bool:
    return 1 <= len(value) <= maximum and all(33 <= ord(character) <= 126 for character in value)


def _signing_key(
    settings: GitLabWebhookSettings,
) -> bytes:
    token = settings.signing_token.get_secret_value()
    _prefix, separator, encoded_key = token.partition("_")

    if not separator:
        raise _invalid_request()

    try:
        return base64.b64decode(
            encoded_key,
            validate=True,
        )
    except ValueError as exc:
        raise _invalid_request() from exc


async def read_bounded_webhook_body(
    request: Request,
) -> bytes:
    """Read a webhook body without exceeding the fixed byte limit."""

    declared_length_text = request.headers.get("content-length")
    declared_length: int | None = None

    if declared_length_text is not None:
        if (
            not declared_length_text.isascii()
            or not declared_length_text.isdecimal()
            or not 1 <= len(declared_length_text) <= 20
        ):
            raise _invalid_request()

        declared_length = int(declared_length_text)

        if declared_length > MAX_WEBHOOK_BODY_BYTES:
            raise _invalid_request()

    body = bytearray()

    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_WEBHOOK_BODY_BYTES:
            raise _invalid_request()

        body.extend(chunk)

    if declared_length is not None and declared_length != len(body):
        raise _invalid_request()

    return bytes(body)


def verify_webhook_request(
    *,
    settings: GitLabWebhookSettings,
    message_id: str,
    timestamp: str,
    received_signatures: str,
    body: bytes,
    current_timestamp: int,
) -> None:
    """Verify freshness and HMAC authenticity without exposing secrets."""

    if not _valid_visible_ascii(
        message_id,
        maximum=MAX_WEBHOOK_ID_CHARACTERS,
    ):
        raise _invalid_request()

    if not timestamp.isascii() or not timestamp.isdecimal() or not 1 <= len(timestamp) <= 20:
        raise _invalid_request()

    request_timestamp = int(timestamp)

    if abs(current_timestamp - request_timestamp) > MAX_WEBHOOK_TIMESTAMP_AGE_SECONDS:
        raise _invalid_request()

    if not 1 <= len(received_signatures) <= MAX_WEBHOOK_SIGNATURE_CHARACTERS:
        raise _invalid_request()

    signatures = received_signatures.split()

    if not 1 <= len(signatures) <= MAX_WEBHOOK_SIGNATURES:
        raise _invalid_request()

    signed_message = b".".join(
        (
            message_id.encode("ascii"),
            timestamp.encode("ascii"),
            body,
        )
    )
    digest = hmac.new(
        _signing_key(settings),
        signed_message,
        hashlib.sha256,
    ).digest()
    expected_signature = "v1," + base64.b64encode(digest).decode("ascii")

    if not any(
        hmac.compare_digest(
            expected_signature,
            signature,
        )
        for signature in signatures
    ):
        raise _invalid_request()

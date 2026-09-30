"""Controlled Telegram notifications for validated pipeline events."""

import json
import logging
from json import JSONDecodeError

import httpx

from bot.config import BotConfigurationError, BotSettings, get_bot_settings
from bot.gitlab_config import (
    GitLabConfigurationError,
    GitLabSettings,
    get_gitlab_settings,
)
from sample_app.deployment_evidence import (
    DeploymentEnvironment,
    DeploymentEvidence,
    DeploymentEvidenceError,
    DeploymentResultStatus,
    GitLabDeploymentEvidenceClient,
    RollbackStatus,
)
from sample_app.security_gate_evidence import (
    GitLabSecurityGateEvidenceClient,
    SecurityGateBlockEvidence,
    SecurityGateEvidenceError,
)
from sample_app.webhook_config import (
    WebhookConfigurationError,
    get_webhook_settings,
)
from sample_app.webhook_events import PipelineEventStatus, PipelineWebhookEvent

TELEGRAM_API_ORIGIN = "https://api.telegram.org"
TELEGRAM_REQUEST_TIMEOUT_SECONDS = 5.0
MAX_TELEGRAM_RESPONSE_BYTES = 65_536
PIPELINE_NOTIFICATION_FAILURE_LOG = "Telegram pipeline notification delivery failed."
SECURITY_GATE_EVIDENCE_FAILURE_LOG = "Security gate evidence lookup failed."
DEPLOYMENT_EVIDENCE_FAILURE_LOG = "Deployment evidence lookup failed."

NOTIFIABLE_PIPELINE_STATUSES = frozenset(
    {
        PipelineEventStatus.SUCCESS,
        PipelineEventStatus.FAILED,
        PipelineEventStatus.CANCELED,
    }
)

_LOGGER = logging.getLogger(__name__)


class PipelineNotificationConfigurationError(RuntimeError):
    """Raised when a safe Telegram notification destination is unavailable."""


class PipelineNotificationDeliveryError(RuntimeError):
    """Raised when Telegram does not confirm notification delivery."""


def _deployment_notification_text(
    event: PipelineWebhookEvent,
    evidence: DeploymentEvidence,
    *,
    staging_site_url: str | None = None,
) -> str:
    """Format only validated deployment state without upstream detail."""

    environment = evidence.environment.value

    if evidence.status is DeploymentResultStatus.DEPLOYED:
        lines = [
            "Deployment update.",
            f"Environment: {environment}.",
            "Status: deployed.",
            "Health verification: passed.",
            f"Commit: {event.sha[:8]}.",
        ]

        if evidence.environment is DeploymentEnvironment.STAGING and staging_site_url is not None:
            lines.append(f"Application: {staging_site_url}")

        return "\n".join(lines)

    if evidence.status is DeploymentResultStatus.CONFIGURATION_FAILED:
        return (
            "Deployment alert.\n"
            f"Environment: {environment}.\n"
            "Status: configuration failed.\n"
            "Rollback: not attempted.\n"
            f"Commit: {event.sha[:8]}."
        )

    if evidence.status is DeploymentResultStatus.PREVIOUS_RELEASE_INVALID:
        return (
            "Deployment alert.\n"
            f"Environment: {environment}.\n"
            "Status: previous release validation failed.\n"
            "Rollback: not attempted.\n"
            f"Commit: {event.sha[:8]}."
        )

    if evidence.status is DeploymentResultStatus.DEPLOYMENT_FAILED:
        return (
            "Deployment alert.\n"
            f"Environment: {environment}.\n"
            "Status: deployment failed.\n"
            "Rollback: unavailable.\n"
            f"Commit: {event.sha[:8]}."
        )

    if evidence.status is DeploymentResultStatus.DEPLOYMENT_FAILED_ROLLED_BACK:
        return (
            "Deployment alert.\n"
            f"Environment: {environment}.\n"
            "Status: deployment failed.\n"
            "Rollback: succeeded.\n"
            "Restored release verification: passed.\n"
            f"Commit: {event.sha[:8]}."
        )

    if (
        evidence.status is DeploymentResultStatus.ROLLBACK_FAILED
        and evidence.rollback is RollbackStatus.FAILED
    ):
        return (
            "Deployment critical alert.\n"
            f"Environment: {environment}.\n"
            "Status: deployment failed.\n"
            "Rollback: failed.\n"
            f"Commit: {event.sha[:8]}."
        )

    raise ValueError("Unsupported validated deployment evidence.")


def _notification_text(
    event: PipelineWebhookEvent,
    *,
    evidence: SecurityGateBlockEvidence | None = None,
    deployment_evidence: DeploymentEvidence | None = None,
    staging_site_url: str | None = None,
) -> str:
    """Format only validated non-sensitive fields as plain text."""

    if deployment_evidence is not None:
        return _deployment_notification_text(
            event,
            deployment_evidence,
            staging_site_url=staging_site_url,
        )

    if evidence is not None:
        return (
            "GitLab security alert.\n"
            "Detected security findings violated the policy.\n"
            f"Blocking findings: {evidence.blocking_findings}.\n"
            f"Total findings: {evidence.total_findings}.\n"
            f"Ref: {event.ref}.\n"
            f"Commit: {event.sha[:8]}."
        )

    return (
        "GitLab pipeline update.\n"
        f"Status: {event.status.value}.\n"
        f"Ref: {event.ref}.\n"
        f"Commit: {event.sha[:8]}."
    )


def _delivery_error() -> PipelineNotificationDeliveryError:
    return PipelineNotificationDeliveryError("Telegram notification delivery failed.")


async def _read_response(response: httpx.Response) -> dict[str, object]:
    body = bytearray()

    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > MAX_TELEGRAM_RESPONSE_BYTES:
            raise _delivery_error()

        body.extend(chunk)

    try:
        payload = json.loads(body)
    except (JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise _delivery_error() from exc

    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise _delivery_error()

    return payload


class TelegramPipelineNotifier:
    """Send bounded plain-text pipeline notifications to configured Admins."""

    def __init__(
        self,
        settings: BotSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not settings.admin_user_ids:
            raise PipelineNotificationConfigurationError(
                "Telegram notification configuration is invalid."
            )

        self._settings = settings
        self._transport = transport

    async def send(
        self,
        event: PipelineWebhookEvent,
        *,
        evidence: SecurityGateBlockEvidence | None = None,
        deployment_evidence: DeploymentEvidence | None = None,
    ) -> bool:
        """Send terminal pipeline states and ignore intermediate states."""

        if event.status not in NOTIFIABLE_PIPELINE_STATUSES:
            return False

        token = self._settings.token.get_secret_value()
        endpoint = f"{TELEGRAM_API_ORIGIN}/bot{token}/sendMessage"
        staging_site_url = (
            None
            if self._settings.staging_site_url is None
            else str(self._settings.staging_site_url)
        )
        request_body = {
            "text": _notification_text(
                event,
                evidence=evidence,
                deployment_evidence=deployment_evidence,
                staging_site_url=staging_site_url,
            ),
            "link_preview_options": {
                "is_disabled": True,
            },
            "protect_content": True,
        }

        try:
            async with httpx.AsyncClient(
                timeout=TELEGRAM_REQUEST_TIMEOUT_SECONDS,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                for chat_id in sorted(self._settings.admin_user_ids):
                    request_body["chat_id"] = chat_id

                    async with client.stream(
                        "POST",
                        endpoint,
                        json=request_body,
                    ) as response:
                        if response.status_code != 200:
                            raise _delivery_error()

                        await _read_response(response)
        except PipelineNotificationDeliveryError:
            raise
        except httpx.HTTPError as exc:
            raise _delivery_error() from exc

        return True


def _build_pipeline_notifier(
    settings: BotSettings,
) -> TelegramPipelineNotifier:
    return TelegramPipelineNotifier(settings)


def _build_deployment_evidence_client(
    settings: GitLabSettings,
) -> GitLabDeploymentEvidenceClient:
    return GitLabDeploymentEvidenceClient(settings)


def _build_security_gate_evidence_client(
    settings: GitLabSettings,
) -> GitLabSecurityGateEvidenceClient:
    return GitLabSecurityGateEvidenceClient(settings)


async def _resolve_deployment_evidence(
    event: PipelineWebhookEvent,
) -> DeploymentEvidence | None:
    try:
        gitlab_settings = get_gitlab_settings()
        webhook_settings = get_webhook_settings()

        if webhook_settings.project_id != gitlab_settings.project_id:
            raise DeploymentEvidenceError("Deployment evidence is unavailable.")

        client = _build_deployment_evidence_client(
            gitlab_settings,
        )
        return await client.get_evidence(event)
    except (
        GitLabConfigurationError,
        WebhookConfigurationError,
        DeploymentEvidenceError,
    ):
        _LOGGER.error(DEPLOYMENT_EVIDENCE_FAILURE_LOG)
        return None


async def _resolve_security_gate_evidence(
    event: PipelineWebhookEvent,
) -> SecurityGateBlockEvidence | None:
    if event.status is not PipelineEventStatus.FAILED:
        return None

    try:
        gitlab_settings = get_gitlab_settings()
        webhook_settings = get_webhook_settings()

        if webhook_settings.project_id != gitlab_settings.project_id:
            raise SecurityGateEvidenceError("Security gate evidence is unavailable.")

        client = _build_security_gate_evidence_client(
            gitlab_settings,
        )
        return await client.get_block_evidence(event)
    except (
        GitLabConfigurationError,
        WebhookConfigurationError,
        SecurityGateEvidenceError,
    ):
        _LOGGER.error(SECURITY_GATE_EVIDENCE_FAILURE_LOG)
        return None


async def notify_pipeline_event(event: PipelineWebhookEvent) -> bool:
    """Load configuration and deliver one controlled notification best-effort."""

    if event.status not in NOTIFIABLE_PIPELINE_STATUSES:
        return False

    try:
        settings = get_bot_settings()
        notifier = _build_pipeline_notifier(settings)
    except (
        BotConfigurationError,
        PipelineNotificationConfigurationError,
    ) as exc:
        raise PipelineNotificationConfigurationError(
            "Telegram notification configuration is invalid."
        ) from exc

    deployment_evidence = await _resolve_deployment_evidence(event)

    if deployment_evidence is not None:
        try:
            return await notifier.send(
                event,
                deployment_evidence=deployment_evidence,
            )
        except PipelineNotificationDeliveryError:
            _LOGGER.error(PIPELINE_NOTIFICATION_FAILURE_LOG)
            return False

    evidence = await _resolve_security_gate_evidence(event)

    try:
        return await notifier.send(
            event,
            evidence=evidence,
        )
    except PipelineNotificationDeliveryError:
        _LOGGER.error(PIPELINE_NOTIFICATION_FAILURE_LOG)
        return False

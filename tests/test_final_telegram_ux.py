"""Focused regression tests for the final Telegram operator experience."""

from pydantic import SecretStr

from bot.config import BotSettings
from bot.handlers import HELP_MESSAGE
from sample_app.deployment_evidence import (
    DeploymentEnvironment,
    DeploymentEvidence,
    DeploymentResultStatus,
    RollbackStatus,
)
from sample_app.webhook_events import PipelineEventStatus, PipelineWebhookEvent
from sample_app.webhook_notifications import _deployment_notification_text


def _token() -> SecretStr:
    return SecretStr("123456789:" + ("A" * 32))


def _event() -> PipelineWebhookEvent:
    return PipelineWebhookEvent(
        pipeline_id=123,
        status=PipelineEventStatus.SUCCESS,
        ref="main",
        sha="a" * 40,
    )


def _successful_deployment(
    environment: DeploymentEnvironment,
) -> DeploymentEvidence:
    return DeploymentEvidence(
        status=DeploymentResultStatus.DEPLOYED,
        environment=environment,
        target_commit_sha="a" * 40,
        rollback=RollbackStatus.NOT_REQUIRED,
    )


def test_help_is_descriptive_and_staging_only() -> None:
    for expected in (
        "/status - Show the latest GitLab pipeline status.",
        "/scan - Launch the approved security-only pipeline.",
        "/deploy_staging - Deploy the validated application to staging.",
    ):
        assert expected in HELP_MESSAGE

    assert "/deploy_production" not in HELP_MESSAGE
    assert "/deploy production" not in HELP_MESSAGE


def test_staging_site_url_is_validated_as_non_secret_http_url() -> None:
    settings = BotSettings(
        token=_token(),
        STAGING_SITE_URL="http://127.0.0.1:18001/",
    )

    assert str(settings.staging_site_url) == "http://127.0.0.1:18001/"


def test_successful_staging_notification_includes_application_url() -> None:
    text = _deployment_notification_text(
        _event(),
        _successful_deployment(DeploymentEnvironment.STAGING),
        staging_site_url="http://127.0.0.1:18001/",
    )

    assert text.endswith("Application: http://127.0.0.1:18001/")


def test_site_url_is_not_added_to_non_staging_deployment() -> None:
    text = _deployment_notification_text(
        _event(),
        _successful_deployment(DeploymentEnvironment.PRODUCTION),
        staging_site_url="http://127.0.0.1:18001/",
    )

    assert "Application:" not in text

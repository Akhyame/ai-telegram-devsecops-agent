"""Regression checks for the final threat-model invariants."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL = ROOT / "docs" / "threat-model.md"


def _content() -> str:
    return THREAT_MODEL.read_text(encoding="utf-8")


def test_threat_model_exists() -> None:
    assert THREAT_MODEL.is_file()


def test_policy_engine_remains_authoritative() -> None:
    content = _content()

    assert "Policy Engine is deterministic and authoritative" in content
    assert "AI cannot authorize, override, deploy, or remediate independently" in content


def test_authorization_and_confirmation_fail_closed() -> None:
    content = _content()

    assert "Invalid Telegram identities fail closed" in content
    assert "RBAC remains deterministic" in content
    assert "one-time and replay-resistant" in content


def test_external_machine_boundaries_are_documented() -> None:
    content = _content()

    assert "Webhook authentication occurs before trusted processing" in content
    assert "Monitoring authentication occurs before trusted processing" in content


def test_secret_and_recovery_boundaries_are_preserved() -> None:
    content = _content()

    assert "Secrets are never committed to Git" in content
    assert "plaintext project backups" in content
    assert "Recovery must preserve these security boundaries" in content


def test_monitoring_cannot_trigger_core_rollback() -> None:
    content = _content()

    assert "Monitoring failure never initiates core application rollback" in content


def test_production_remains_outside_validated_scope() -> None:
    content = _content()

    assert "Production remains unprovisioned" in content
    assert "not production certification" in content

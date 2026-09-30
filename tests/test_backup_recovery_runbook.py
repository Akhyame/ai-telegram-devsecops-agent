"""Regression checks for the documented backup and recovery contract."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "backup-recovery.md"

REQUIRED_RECOVERY_FILES = (
    ".gitlab-ci.yml",
    ".env.example",
    "pyproject.toml",
    "deployment/compose.yml",
    "deployment/compose.staging.yml",
    "deployment/monitoring.sh",
    "monitoring/prometheus/prometheus.yml",
    "monitoring/prometheus/alerts.yml",
    "monitoring/alertmanager/alertmanager.yml",
)


def test_recovery_runbook_exists() -> None:
    assert RUNBOOK.is_file()


def test_required_recovery_sources_exist() -> None:
    for relative_path in REQUIRED_RECOVERY_FILES:
        assert (ROOT / relative_path).is_file(), relative_path


def test_recovery_runbook_excludes_plaintext_secret_backups() -> None:
    content = RUNBOOK.read_text(encoding="utf-8")

    assert "Plaintext `.env` files" in content
    assert "SSH private keys" in content
    assert "Never archive as project backup" in content
    assert "Re-provision" in content


def test_recovery_runbook_preserves_security_boundaries() -> None:
    content = RUNBOOK.read_text(encoding="utf-8")

    assert "deterministic Policy Engine remains" in content
    assert "no production deployment occurred" in content
    assert "monitoring-state loss must never trigger a core application rollback" in content

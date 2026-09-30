"""Offline tests for hardened Docker Compose deployment artifacts."""

from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_BASE_COMPOSE = _REPOSITORY_ROOT / "deployment" / "compose.yml"
_STAGING_COMPOSE = _REPOSITORY_ROOT / "deployment" / "compose.staging.yml"
_PRODUCTION_COMPOSE = _REPOSITORY_ROOT / "deployment" / "compose.production.yml"
_DOCKERFILE = _REPOSITORY_ROOT / "Dockerfile"
_DOCKERIGNORE = _REPOSITORY_ROOT / ".dockerignore"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_base_compose_applies_hardening_to_both_services() -> None:
    compose = _read(_BASE_COMPOSE)

    assert compose.count("<<: *service-hardening") == 2

    for required_control in (
        'user: "10001:10001"',
        "read_only: true",
        "init: true",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "pids_limit: 128",
        "mem_limit: 512m",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",  # noqa: S108
        'max-size: "10m"',
        'max-file: "3"',
    ):
        assert required_control in compose

    for forbidden_control in (
        "privileged: true",
        "/var/run/docker.sock",
        "network_mode: host",
        "pid: host",
        "user: root",
    ):
        assert forbidden_control not in compose


def test_base_compose_uses_required_commit_addressed_image() -> None:
    compose = _read(_BASE_COMPOSE)

    assert "DEPLOYMENT_IMAGE_REPOSITORY is required" in compose
    assert "DEPLOYMENT_COMMIT_SHA is required" in compose
    assert ":latest" not in compose


def test_api_and_bot_have_separate_commands_and_networks() -> None:
    compose = _read(_BASE_COMPOSE)

    assert "sample_app.main:app" in compose
    assert "- bot" in compose
    assert "- api_egress" in compose
    assert "- bot_egress" in compose
    assert compose.count("driver: bridge") == 3
    assert (
        """  monitoring:
    driver: bridge
    internal: true"""
        in compose
    )


def test_staging_override_is_loopback_only_and_secret_external() -> None:
    compose = _read(_STAGING_COMPOSE)

    assert "name: ai-devsecops-staging" in compose
    assert "SAMPLE_APP_ENVIRONMENT: staging" in compose
    assert 'published: "18000"' in compose
    assert "host_ip: 127.0.0.1" in compose
    assert "STAGING_API_ENV_FILE is required" in compose
    assert "STAGING_BOT_ENV_FILE is required" in compose
    assert "TELEGRAM_BOT_TOKEN" not in compose
    assert "GITLAB_DEPLOY_API_TOKEN" not in compose


def test_production_override_is_loopback_only_and_secret_external() -> None:
    compose = _read(_PRODUCTION_COMPOSE)

    assert "name: ai-devsecops-production" in compose
    assert "SAMPLE_APP_ENVIRONMENT: production" in compose
    assert 'published: "8000"' in compose
    assert "host_ip: 127.0.0.1" in compose
    assert "PRODUCTION_API_ENV_FILE is required" in compose
    assert "PRODUCTION_BOT_ENV_FILE is required" in compose
    assert "TELEGRAM_BOT_TOKEN" not in compose
    assert "GITLAB_DEPLOY_API_TOKEN" not in compose


def test_runtime_image_contains_all_required_packages() -> None:
    dockerfile = _read(_DOCKERFILE)

    for package in (
        "agent",
        "api",
        "bot",
        "deployment",
        "gitlab_client",
        "policy_engine",
        "sample_app",
    ):
        assert f"COPY {package} ./{package}" in dockerfile

    assert "USER 10001:10001" in dockerfile


def test_docker_build_context_allows_runtime_packages() -> None:
    dockerignore = _read(_DOCKERIGNORE)

    for package in (
        "agent",
        "api",
        "bot",
        "deployment",
        "gitlab_client",
        "policy_engine",
        "sample_app",
    ):
        assert f"!{package}/" in dockerignore
        assert f"!{package}/**" in dockerignore

    assert "!.env" not in dockerignore
    assert "!tests/" not in dockerignore
    assert "!.git/" not in dockerignore


def test_prometheus_is_profiled_and_uses_remote_safe_config_volume() -> None:
    compose = _read(_BASE_COMPOSE)

    assert (
        """  prometheus:
    image: "prom/prometheus:v3.13.2"
    profiles:
      - monitoring"""
        in compose
    )

    assert "../monitoring/prometheus/prometheus.yml" not in compose
    assert "prometheus_config:/etc/prometheus:ro" in compose

    assert (
        """volumes:
  prometheus_data:
  prometheus_config:"""
        in compose
    )


def test_monitoring_services_have_bounded_log_rotation() -> None:
    compose = _read(_BASE_COMPOSE)
    lines = compose.splitlines()

    for service in ("prometheus", "alertmanager"):
        start = lines.index(f"  {service}:")

        end = len(lines)

        for index in range(start + 1, len(lines)):
            line = lines[index]

            if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":"):
                end = index
                break

        section = "\n".join(lines[start:end])

        assert "logging:" in section
        assert "driver: json-file" in section
        assert 'max-size: "10m"' in section
        assert 'max-file: "3"' in section

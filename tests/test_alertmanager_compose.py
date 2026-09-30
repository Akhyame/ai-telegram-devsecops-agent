from pathlib import Path

COMPOSE_TEXT = Path("deployment/compose.yml").read_text(encoding="utf-8")


def _alertmanager_block() -> str:
    marker = "\n  alertmanager:\n"

    assert marker in COMPOSE_TEXT

    remainder = COMPOSE_TEXT.split(marker, 1)[1]
    return remainder.split("\nnetworks:\n", 1)[0]


def test_alertmanager_uses_pinned_image_and_monitoring_profile() -> None:
    block = _alertmanager_block()

    assert "image: prom/alertmanager:v0.33.1" in block
    assert "profiles:" in block
    assert "- monitoring" in block


def test_alertmanager_has_no_host_port() -> None:
    block = _alertmanager_block()

    assert "\n    ports:" not in block
    assert '      - "9093"' in block


def test_alertmanager_is_attached_only_to_monitoring_network() -> None:
    block = _alertmanager_block()

    assert "    networks:\n      - monitoring" in block
    assert "api_egress" not in block
    assert "bot_egress" not in block


def test_monitoring_network_remains_internal() -> None:
    assert "monitoring:" in COMPOSE_TEXT
    assert "internal: true" in COMPOSE_TEXT


def test_alertmanager_runtime_is_hardened() -> None:
    block = _alertmanager_block()

    assert "restart: unless-stopped" in block
    assert "init: true" in block
    assert "read_only: true" in block

    assert "cap_drop:" in block
    assert "- ALL" in block

    assert "no-new-privileges:true" in block

    assert "pids_limit: 128" in block
    assert "cpus: 0.25" in block
    assert "mem_limit: 256m" in block

    assert "/tmp" in block  # noqa: S108


def test_alertmanager_uses_named_config_and_data_volumes() -> None:
    block = _alertmanager_block()

    assert "alertmanager_config:/etc/alertmanager:ro" in block
    assert "alertmanager_data:/alertmanager" in block

    assert "alertmanager_config:" in COMPOSE_TEXT
    assert "alertmanager_data:" in COMPOSE_TEXT


def test_alertmanager_uses_explicit_runtime_contract() -> None:
    block = _alertmanager_block()

    assert "--config.file=/etc/alertmanager/alertmanager.yml" in block
    assert "--enable-feature=utf8-strict-mode" in block
    assert "--storage.path=/alertmanager" in block
    assert "--web.listen-address=0.0.0.0:9093" in block


def test_alertmanager_has_no_direct_telegram_configuration() -> None:
    block = _alertmanager_block().lower()

    assert "telegram" not in block
    assert "bot_token" not in block
    assert "api.telegram.org" not in block

"""Offline contracts for isolated Alertmanager monitoring deployment."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_RELEASE = _ROOT / "deployment" / "monitoring.sh"


def _release() -> str:
    return _RELEASE.read_text(encoding="utf-8")


def test_alertmanager_input_fails_closed() -> None:
    release = _release()

    assert "ALERTMANAGER_CONFIG_PATH" in release
    assert "Alertmanager configuration is unavailable." in release
    assert "Alertmanager configuration size is invalid." in release
    assert "Alertmanager configuration exceeds size limit." in release
    assert 'wc -c < "$ALERTMANAGER_CONFIG_PATH"' in release


def test_alertmanager_uses_remote_safe_named_config_volume() -> None:
    release = _release()

    assert 'eq .Destination "/etc/alertmanager"' in release
    assert '"${alertmanager_config_volume}:/config"' in release
    assert '"$ALERTMANAGER_CONFIG_PATH"' in release
    assert '"${ALERTMANAGER_HELPER_NAME}:/config/alertmanager.yml"' in release


def test_alertmanager_config_validation_is_network_isolated() -> None:
    release = _release()

    assert "--entrypoint /bin/amtool" in release
    assert "check-config /etc/alertmanager/alertmanager.yml" in release
    assert "--enable-feature=utf8-strict-mode" in release
    assert '"prom/alertmanager:v0.33.1"' in release
    assert "--network none" in release
    assert "--read-only" in release
    assert "--cap-drop ALL" in release
    assert "--security-opt no-new-privileges" in release


def test_alertmanager_runtime_validation_is_bounded() -> None:
    release = _release()

    assert "ALERTMANAGER_READINESS_ATTEMPT=" in release
    assert "http://127.0.0.1:9093/-/ready" in release
    assert 'docker port "$alertmanager_id" 9093/tcp' in release
    assert "ALERTMANAGER_READY=true" in release
    assert "ALERTMANAGER_HOST_PORT_PUBLISHED=false" in release


def test_alertmanager_is_restricted_to_monitoring_network() -> None:
    release = _release()

    assert 'expected_network="${PROJECT_NAME}_monitoring"' in release
    assert 'alertmanager_network_names="$(' in release
    assert '"$alertmanager_network_names" != "$expected_network"' in release


def test_alertmanager_failure_never_rolls_back_core() -> None:
    release = _release()

    assert "CORE_APPLICATION_ROLLBACK_ATTEMPTED=false" in release
    assert "ROLLBACK_RESULT=" not in release
    assert "compose_command down" not in release


def test_alertmanager_receiver_secret_is_extracted_fail_closed() -> None:
    release = _release()

    assert "DEPLOYMENT_API_ENV_FILE" in release
    assert "ALERTMANAGER_RECEIVER_TOKEN=" in release
    assert 'ALERTMANAGER_RECEIVER_TOKEN_TMP="$(mktemp)"' in release
    assert 'wc -c < "$DEPLOYMENT_API_ENV_FILE"' in release
    assert 'api_env_size" -gt 262144' in release

    assert "found += 1" in release
    assert "if (found != 1)" in release
    assert "length(value) != 50" in release
    assert 'substr(value, 1, 6) != "amsec_"' in release
    assert "length(encoded) != 44" in release
    assert 'substr(encoded, 44, 1) != "="' in release
    assert "final_data_character" in release
    assert "^[AEIMQUYcgkosw048]$" in release

    assert 'source "$DEPLOYMENT_API_ENV_FILE"' not in release
    assert '. "$DEPLOYMENT_API_ENV_FILE"' not in release


def test_alertmanager_receiver_secret_temp_file_is_bounded_and_cleaned() -> None:
    release = _release()

    assert "umask 077" in release
    assert 'chmod 600 "$ALERTMANAGER_RECEIVER_TOKEN_TMP"' in release
    assert "receiver_token_size" in release
    assert 'receiver_token_size" != "50"' in release
    assert 'rm -f "$ALERTMANAGER_RECEIVER_TOKEN_TMP"' in release

    cleanup_start = release.index("cleanup_helper() {")
    cleanup_end = release.index("\n}", cleanup_start)
    cleanup_block = release[cleanup_start:cleanup_end]

    assert 'rm -f "$ALERTMANAGER_RECEIVER_TOKEN_TMP"' in cleanup_block


def test_alertmanager_receiver_secret_helper_is_isolated() -> None:
    release = _release()

    helper_start = release.index(
        'if ! docker run \\\n    --rm \\\n    --name "$ALERTMANAGER_SECRET_HELPER_NAME"'
    )
    helper_end = release.index(
        '< "$ALERTMANAGER_RECEIVER_TOKEN_TMP"; then',
        helper_start,
    )
    helper_block = release[helper_start:helper_end]

    assert "--interactive" in helper_block
    assert "--network none" in helper_block
    assert "--read-only" in helper_block
    assert "--user 0:0" in helper_block
    assert "--cap-drop ALL" in helper_block
    assert "--cap-add CHOWN" in helper_block
    assert "--security-opt no-new-privileges" in helper_block
    assert '"${alertmanager_config_volume}:/config"' in helper_block
    assert "--entrypoint /bin/sh" in helper_block

    assert "chown nobody:nobody /config/receiver-token" in helper_block
    assert "chmod 0400 /config/receiver-token" in helper_block

    assert "ALERTMANAGER_RECEIVER_TOKEN=" not in helper_block
    assert "amsec_" not in helper_block


def test_alertmanager_receiver_secret_uses_stdin_not_command_argument() -> None:
    release = _release()

    assert '< "$ALERTMANAGER_RECEIVER_TOKEN_TMP"' in release

    secret_helper_start = release.index('--name "$ALERTMANAGER_SECRET_HELPER_NAME"')
    secret_helper_end = release.index(
        '< "$ALERTMANAGER_RECEIVER_TOKEN_TMP"; then',
        secret_helper_start,
    )
    helper_block = release[secret_helper_start:secret_helper_end]

    assert "$ALERTMANAGER_RECEIVER_TOKEN_TMP" not in helper_block


def test_alertmanager_secret_is_provisioned_before_config_validation() -> None:
    release = _release()

    provision_index = release.index("cat > /config/receiver-token")
    temp_cleanup_index = release.index(
        'rm -f "$ALERTMANAGER_RECEIVER_TOKEN_TMP"',
        provision_index,
    )
    amtool_index = release.index(
        "check-config /etc/alertmanager/alertmanager.yml",
        provision_index,
    )

    assert provision_index < temp_cleanup_index < amtool_index


def test_alertmanager_receiver_secret_failure_never_rolls_back_core() -> None:
    release = _release()

    assert "Alertmanager receiver credential configuration is invalid." in release
    assert "Alertmanager receiver credential staging permissions failed." in release
    assert "Alertmanager receiver credential provisioning failed." in release
    assert "CORE_APPLICATION_ROLLBACK_ATTEMPTED=false" in release


def test_alertmanager_config_permissions_are_normalized_before_validation() -> None:
    release = _release()

    copy_index = release.index('"${ALERTMANAGER_HELPER_NAME}:/config/alertmanager.yml"')
    normalize_index = release.index(
        "chmod 0444 /config/alertmanager.yml",
        copy_index,
    )
    config_owner_index = release.index(
        "chown nobody:nobody /config/alertmanager.yml",
        normalize_index,
    )
    secret_index = release.index(
        "cat > /config/receiver-token",
        config_owner_index,
    )
    amtool_index = release.index(
        "check-config /etc/alertmanager/alertmanager.yml",
        secret_index,
    )

    assert copy_index < normalize_index
    assert normalize_index < config_owner_index
    assert config_owner_index < secret_index
    assert secret_index < amtool_index

    assert "Alertmanager configuration permissions normalization failed." in release


def test_alertmanager_secret_permissions_are_set_before_chown() -> None:
    release = _release()

    chmod_index = release.index("chmod 0400 /config/receiver-token")
    chown_index = release.index("chown nobody:nobody /config/receiver-token")

    assert chmod_index < chown_index
    assert "--cap-drop ALL" in release
    assert "--cap-add CHOWN" in release


def test_receiver_token_survives_mid_deployment_cleanup_until_provisioning() -> None:
    release = _release()

    staged_index = release.index('ALERTMANAGER_RECEIVER_TOKEN_TMP="$(mktemp)"')

    secret_helper_index = release.index(
        "cat > /config/receiver-token",
        staged_index,
    )

    window = release[staged_index:secret_helper_index]

    assert "\ncleanup_helper\n" not in window
    assert "\ncleanup_containers\n" in window

    provision_input_index = release.index(
        '< "$ALERTMANAGER_RECEIVER_TOKEN_TMP"',
        secret_helper_index,
    )

    cleanup_index = release.index(
        'rm -f "$ALERTMANAGER_RECEIVER_TOKEN_TMP"',
        provision_input_index,
    )

    assert provision_input_index < cleanup_index


def test_alertmanager_secret_volume_directory_is_normalized_before_write() -> None:
    release = _release()

    helper_index = release.index("cat > /config/receiver-token")

    command_start = release.rfind(
        "-eu -c '",
        0,
        helper_index,
    )

    command = release[command_start:helper_index]

    chown_index = command.index("chown 0:0 /config")
    chmod_index = command.index("chmod 0755 /config")

    assert chown_index < chmod_index
    assert "--cap-drop ALL" in release
    assert "--cap-add CHOWN" in release

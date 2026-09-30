from pathlib import Path

_SCRIPT = Path("deployment/monitoring.sh")


def test_receiver_token_is_removed_before_secure_reprovisioning() -> None:
    script = _SCRIPT.read_text(encoding="utf-8")

    expected = (
        "rm -f /config/receiver-token; "
        "umask 077; "
        "cat > /config/receiver-token; "
        "chmod 0400 /config/receiver-token; "
        "chown nobody:nobody /config/receiver-token"
    )

    assert expected in script


def test_receiver_token_helper_does_not_add_dac_override() -> None:
    script = _SCRIPT.read_text(encoding="utf-8")

    assert "--cap-add DAC_OVERRIDE" not in script
    assert "--cap-add DAC_READ_SEARCH" not in script

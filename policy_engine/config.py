import tomllib
from pathlib import Path

from policy_engine.errors import PolicyConfigurationError
from policy_engine.models import SecurityPolicy, Severity

_SUPPORTED_SCHEMA_VERSION = 1

_ROOT_KEYS = {
    "schema_version",
    "policy",
}

_POLICY_KEYS = {
    "blocked_severities",
    "block_on_unknown",
}

_REQUIRED_BLOCKED_SEVERITIES = {
    Severity.HIGH,
    Severity.CRITICAL,
}


def load_security_policy(
    policy_path: str | Path,
) -> SecurityPolicy:
    path = Path(policy_path)

    try:
        raw_policy = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyConfigurationError(f"Unable to read security policy: {path.name}") from exc

    try:
        payload = tomllib.loads(raw_policy)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyConfigurationError(f"Invalid TOML in security policy: {path.name}") from exc

    _validate_keys(
        payload,
        _ROOT_KEYS,
        "Security policy root",
    )

    schema_version = payload["schema_version"]
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != _SUPPORTED_SCHEMA_VERSION
    ):
        raise PolicyConfigurationError("Security policy has unsupported schema_version")

    policy_data = payload["policy"]
    if not isinstance(policy_data, dict):
        raise PolicyConfigurationError("Security policy policy section must be a table")

    _validate_keys(
        policy_data,
        _POLICY_KEYS,
        "Security policy policy section",
    )

    blocked_severities = _parse_blocked_severities(policy_data["blocked_severities"])

    block_on_unknown = policy_data["block_on_unknown"]
    if not isinstance(block_on_unknown, bool):
        raise PolicyConfigurationError("Security policy has invalid block_on_unknown")

    return SecurityPolicy(
        blocked_severities=blocked_severities,
        block_on_unknown=block_on_unknown,
    )


def _parse_blocked_severities(
    raw_severities: object,
) -> frozenset[Severity]:
    if not isinstance(raw_severities, list):
        raise PolicyConfigurationError("Security policy blocked_severities must be a list")

    severities: list[Severity] = []

    for severity_index, raw_severity in enumerate(raw_severities):
        if not isinstance(raw_severity, str) or not raw_severity.strip():
            raise PolicyConfigurationError(
                f"Security policy has invalid blocked severity at index {severity_index}"
            )

        try:
            severity = Severity(raw_severity.strip().lower())
        except ValueError as exc:
            raise PolicyConfigurationError(
                f"Security policy has unsupported blocked severity at index {severity_index}"
            ) from exc

        if severity is Severity.UNKNOWN:
            raise PolicyConfigurationError(
                "Security policy must configure unknown severity through block_on_unknown"
            )

        severities.append(severity)

    if len(severities) != len(set(severities)):
        raise PolicyConfigurationError("Security policy contains duplicate blocked severities")

    normalized_severities = frozenset(severities)

    if not _REQUIRED_BLOCKED_SEVERITIES.issubset(normalized_severities):
        raise PolicyConfigurationError("Security policy must block high and critical severities")

    return normalized_severities


def _validate_keys(
    data: dict[str, object],
    expected_keys: set[str],
    context: str,
) -> None:
    if set(data) != expected_keys:
        raise PolicyConfigurationError(f"{context} has missing or unsupported keys")

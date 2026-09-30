from pathlib import Path

import pytest

from policy_engine.config import load_security_policy
from policy_engine.errors import PolicyConfigurationError
from policy_engine.models import SecurityPolicy, Severity


def _write_policy(
    tmp_path: Path,
    content: str,
) -> Path:
    policy_path = tmp_path / "security-policy.toml"
    policy_path.write_text(
        content,
        encoding="utf-8",
    )
    return policy_path


def _valid_policy(
    *,
    blocked_severities: str = '"high", "critical"',
    block_on_unknown: str = "true",
) -> str:
    return f"""
schema_version = 1

[policy]
blocked_severities = [{blocked_severities}]
block_on_unknown = {block_on_unknown}
"""


def test_repository_security_policy_matches_baseline() -> None:
    policy = load_security_policy(Path("security-policy.toml"))

    assert policy == SecurityPolicy(
        blocked_severities=frozenset(
            {
                Severity.HIGH,
                Severity.CRITICAL,
            }
        ),
        block_on_unknown=True,
    )


def test_load_security_policy_accepts_stricter_policy(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=('"medium", "high", "critical"'),
            block_on_unknown="false",
        ),
    )

    policy = load_security_policy(policy_path)

    assert policy.blocked_severities == frozenset(
        {
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        }
    )
    assert policy.block_on_unknown is False


def test_load_security_policy_normalizes_case_and_whitespace(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=('" HIGH ", "Critical"'),
        ),
    )

    policy = load_security_policy(policy_path)

    assert policy.blocked_severities == frozenset(
        {
            Severity.HIGH,
            Severity.CRITICAL,
        }
    )


def test_load_security_policy_rejects_missing_file(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "missing.toml"

    with pytest.raises(
        PolicyConfigurationError,
        match="Unable to read security policy",
    ):
        load_security_policy(policy_path)


def test_load_security_policy_rejects_invalid_toml(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        "schema_version = [",
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="Invalid TOML in security policy",
    ):
        load_security_policy(policy_path)


@pytest.mark.parametrize(
    "policy_content",
    [
        """
[policy]
blocked_severities = ["high", "critical"]
block_on_unknown = true
""",
        """
schema_version = 1
unexpected = true

[policy]
blocked_severities = ["high", "critical"]
block_on_unknown = true
""",
    ],
)
def test_load_security_policy_rejects_invalid_root_keys(
    tmp_path: Path,
    policy_content: str,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        policy_content,
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="root has missing or unsupported keys",
    ):
        load_security_policy(policy_path)


@pytest.mark.parametrize(
    "schema_version",
    [
        "true",
        "1.0",
        "2",
        '"1"',
    ],
)
def test_load_security_policy_rejects_unsupported_schema(
    tmp_path: Path,
    schema_version: str,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        f"""
schema_version = {schema_version}

[policy]
blocked_severities = ["high", "critical"]
block_on_unknown = true
""",
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="unsupported schema_version",
    ):
        load_security_policy(policy_path)


def test_load_security_policy_requires_policy_table(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        """
schema_version = 1
policy = "invalid"
""",
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="policy section must be a table",
    ):
        load_security_policy(policy_path)


@pytest.mark.parametrize(
    "policy_content",
    [
        """
schema_version = 1

[policy]
blocked_severities = ["high", "critical"]
""",
        """
schema_version = 1

[policy]
blocked_severities = ["high", "critical"]
block_on_unknown = true
unexpected = true
""",
    ],
)
def test_load_security_policy_rejects_invalid_policy_keys(
    tmp_path: Path,
    policy_content: str,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        policy_content,
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="policy section has missing or unsupported keys",
    ):
        load_security_policy(policy_path)


@pytest.mark.parametrize(
    "blocked_severities",
    [
        '"high"',
        "true",
        "1",
        '{ value = "high" }',
    ],
)
def test_load_security_policy_requires_severity_list(
    tmp_path: Path,
    blocked_severities: str,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        f"""
schema_version = 1

[policy]
blocked_severities = {blocked_severities}
block_on_unknown = true
""",
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="blocked_severities must be a list",
    ):
        load_security_policy(policy_path)


@pytest.mark.parametrize(
    "blocked_severities",
    [
        '"high", "critical", 1',
        '"high", "critical", true',
        '"high", "critical", ""',
        '"high", "critical", "   "',
    ],
)
def test_load_security_policy_rejects_invalid_severity_items(
    tmp_path: Path,
    blocked_severities: str,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=blocked_severities,
        ),
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="invalid blocked severity",
    ):
        load_security_policy(policy_path)


def test_load_security_policy_rejects_unsupported_severity(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=('"high", "critical", "future-severity"'),
        ),
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="unsupported blocked severity",
    ):
        load_security_policy(policy_path)


def test_load_security_policy_rejects_unknown_in_severity_list(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=('"high", "critical", "unknown"'),
        ),
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="through block_on_unknown",
    ):
        load_security_policy(policy_path)


def test_load_security_policy_rejects_duplicate_severity(
    tmp_path: Path,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=('"high", "critical", "HIGH"'),
        ),
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="duplicate blocked severities",
    ):
        load_security_policy(policy_path)


@pytest.mark.parametrize(
    "blocked_severities",
    [
        "",
        '"high"',
        '"critical"',
        '"medium", "high"',
        '"medium", "critical"',
    ],
)
def test_load_security_policy_requires_security_baseline(
    tmp_path: Path,
    blocked_severities: str,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=blocked_severities,
        ),
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="must block high and critical",
    ):
        load_security_policy(policy_path)


@pytest.mark.parametrize(
    "block_on_unknown",
    [
        '"true"',
        "1",
        "1.0",
        '["true"]',
    ],
)
def test_load_security_policy_requires_boolean_unknown_rule(
    tmp_path: Path,
    block_on_unknown: str,
) -> None:
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            block_on_unknown=block_on_unknown,
        ),
    )

    with pytest.raises(
        PolicyConfigurationError,
        match="invalid block_on_unknown",
    ):
        load_security_policy(policy_path)


def test_load_security_policy_does_not_propagate_untrusted_value(
    tmp_path: Path,
) -> None:
    untrusted_value = "DO-NOT-PROPAGATE-THIS-VALUE"
    policy_path = _write_policy(
        tmp_path,
        _valid_policy(
            blocked_severities=(f'"high", "critical", "{untrusted_value}"'),
        ),
    )

    with pytest.raises(
        PolicyConfigurationError,
    ) as exc_info:
        load_security_policy(policy_path)

    assert untrusted_value not in str(exc_info.value)

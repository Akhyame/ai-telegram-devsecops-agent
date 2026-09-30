"""Offline tests for the local-only AI configuration boundary."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from agent.config import (
    AIConfigurationError,
    get_ai_settings,
)

_ENVIRONMENT_NAMES = (
    "AI_PROVIDER",
    "OLLAMA_API_URL",
    "OLLAMA_MODEL",
    "AI_REQUEST_TIMEOUT_SECONDS",
    "AI_MAX_OUTPUT_CHARS",
)


@pytest.fixture(autouse=True)
def _isolate_ai_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Iterator[None]:
    monkeypatch.chdir(tmp_path)

    for name in _ENVIRONMENT_NAMES:
        monkeypatch.delenv(name, raising=False)

    get_ai_settings.cache_clear()

    yield

    get_ai_settings.cache_clear()


def test_defaults_are_local_fixed_and_bounded() -> None:
    settings = get_ai_settings()

    assert settings.provider == "ollama-local"
    assert settings.api_url == "http://127.0.0.1:11434/api"
    assert settings.model == "qwen3.5:4b"
    assert settings.request_timeout_seconds == 60
    assert settings.max_output_chars == 1200


def test_fixed_vmware_host_api_url_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deployment_api_url = "http://192.168.220.1:11434/api"
    monkeypatch.setenv(
        "OLLAMA_API_URL",
        deployment_api_url,
    )

    settings = get_ai_settings()

    assert settings.api_url == deployment_api_url


def test_settings_are_cached() -> None:
    first = get_ai_settings()
    second = get_ai_settings()

    assert first is second


@pytest.mark.parametrize(
    ("name", "unsafe_value"),
    (
        ("AI_PROVIDER", "openai"),
        ("AI_PROVIDER", "ollama-cloud"),
        ("AI_PROVIDER", ""),
        ("OLLAMA_API_URL", "https://ollama.com/api"),
        ("OLLAMA_API_URL", "http://localhost:11434/api"),
        ("OLLAMA_API_URL", "http://127.0.0.1:11434/api/"),
        ("OLLAMA_API_URL", "http://192.168.1.10:11434/api"),
        ("OLLAMA_API_URL", "http://192.168.220.2:11434/api"),
        ("OLLAMA_API_URL", "https://192.168.220.1:11434/api"),
        ("OLLAMA_API_URL", "http://192.168.220.1:11434/api/"),
        ("OLLAMA_MODEL", "qwen3.5:4b-cloud"),
        ("OLLAMA_MODEL", "qwen3.5:9b"),
        ("OLLAMA_MODEL", ""),
    ),
)
def test_untrusted_provider_url_or_model_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    unsafe_value: str,
) -> None:
    monkeypatch.setenv(name, unsafe_value)

    with pytest.raises(
        AIConfigurationError,
        match=r"\ALocal AI configuration is invalid\.\Z",
    ) as error:
        get_ai_settings()

    if unsafe_value:
        assert unsafe_value not in str(error.value)


@pytest.mark.parametrize(
    ("name", "unsafe_value"),
    (
        ("AI_REQUEST_TIMEOUT_SECONDS", "0"),
        ("AI_REQUEST_TIMEOUT_SECONDS", "9"),
        ("AI_REQUEST_TIMEOUT_SECONDS", "121"),
        ("AI_REQUEST_TIMEOUT_SECONDS", "not-a-number"),
        ("AI_MAX_OUTPUT_CHARS", "0"),
        ("AI_MAX_OUTPUT_CHARS", "199"),
        ("AI_MAX_OUTPUT_CHARS", "2001"),
        ("AI_MAX_OUTPUT_CHARS", "not-a-number"),
    ),
)
def test_unsafe_numeric_limits_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    unsafe_value: str,
) -> None:
    monkeypatch.setenv(name, unsafe_value)

    with pytest.raises(
        AIConfigurationError,
        match=r"\ALocal AI configuration is invalid\.\Z",
    ) as error:
        get_ai_settings()

    if unsafe_value:
        assert unsafe_value not in str(error.value)


@pytest.mark.parametrize(
    (
        "timeout",
        "max_output",
    ),
    (
        ("10", "200"),
        ("120", "2000"),
    ),
)
def test_valid_boundary_values_are_accepted(
    monkeypatch: pytest.MonkeyPatch,
    timeout: str,
    max_output: str,
) -> None:
    monkeypatch.setenv(
        "AI_REQUEST_TIMEOUT_SECONDS",
        timeout,
    )
    monkeypatch.setenv(
        "AI_MAX_OUTPUT_CHARS",
        max_output,
    )

    settings = get_ai_settings()

    assert settings.request_timeout_seconds == int(timeout)
    assert settings.max_output_chars == int(max_output)

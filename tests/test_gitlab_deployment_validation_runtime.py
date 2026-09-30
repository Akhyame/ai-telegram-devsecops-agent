"""CI contract tests for deployment validation runtime dependencies."""

from pathlib import Path

_CI_TEXT = Path(".gitlab-ci.yml").read_text(encoding="utf-8")


def _deployment_validation_template() -> str:
    start = _CI_TEXT.index(".deployment_validation:\n")
    end = _CI_TEXT.index(
        "\nvalidate_staging_deployment:",
        start,
    )

    return _CI_TEXT[start:end]


def test_deployment_validation_installs_runtime_dependencies() -> None:
    template = _deployment_validation_template()

    assert "  extends: .python_pip_cache\n" in template
    assert ("  before_script:\n    - python -m pip install .\n") in template
    assert template.index("  before_script:") < template.index("  script:")

from importlib import import_module

import pytest

PROJECT_PACKAGES = (
    "agent",
    "api",
    "bot",
    "gitlab_client",
    "policy_engine",
    "sample_app",
)


@pytest.mark.parametrize("package_name", PROJECT_PACKAGES)
def test_project_package_is_importable(package_name: str) -> None:
    module = import_module(package_name)

    assert module.__name__ == package_name

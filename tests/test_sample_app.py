"""Automated tests for the FastAPI sample application."""

import io
import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from sample_app.main import app, logger


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Provide an isolated HTTP test client."""

    with TestClient(app) as test_client:
        yield test_client


def test_liveness_endpoint(client: TestClient) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_endpoint(client: TestClient) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_service_info_endpoint(client: TestClient) -> None:
    response = client.get("/api/v1/info")

    assert response.status_code == 200
    assert response.json() == {
        "name": "AI DevSecOps Sample Application",
        "version": "0.1.0",
        "environment": "development",
    }


def test_metrics_endpoint(client: TestClient) -> None:
    client.get("/health/live")
    response = client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert "sample_app_http_requests_total" in response.text
    assert 'route="/health/live"' in response.text


def test_openapi_is_available_in_development(client: TestClient) -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["version"] == "0.1.0"


def test_unknown_route_returns_not_found(client: TestClient) -> None:
    response = client.get("/does-not-exist")

    assert response.status_code == 404


def test_request_log_excludes_query_parameters(
    client: TestClient,
) -> None:
    log_stream = io.StringIO()
    handler = logger.handlers[0]
    original_stream = handler.stream
    handler.setStream(log_stream)

    try:
        response = client.get("/health/live?token=do-not-log")
    finally:
        handler.setStream(original_stream)

    assert response.status_code == 200

    log_text = log_stream.getvalue().strip()
    payload = json.loads(log_text.splitlines()[-1])

    assert payload["message"] == "http_request"
    assert payload["http_method"] == "GET"
    assert payload["http_route"] == "/health/live"
    assert payload["http_status_code"] == 200
    assert "duration_ms" in payload
    assert "do-not-log" not in log_text
    assert "token" not in log_text


def test_metrics_collapse_unknown_paths_to_bounded_label(
    client: TestClient,
) -> None:
    client.get("/unknown-resource/123?token=dummy-one")
    client.get("/unknown-resource/456?token=dummy-two")

    response = client.get("/metrics")

    assert response.status_code == 200
    assert 'route="unmatched"' in response.text

    assert "/unknown-resource/123" not in response.text
    assert "/unknown-resource/456" not in response.text
    assert "dummy-one" not in response.text
    assert "dummy-two" not in response.text

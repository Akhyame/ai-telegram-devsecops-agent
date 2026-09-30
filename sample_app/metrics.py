"""Prometheus metrics used by the sample application."""

from prometheus_client import Counter, Histogram

HTTP_REQUESTS_TOTAL = Counter(
    "sample_app_http_requests_total",
    "Total number of HTTP requests processed.",
    ("method", "route", "status_code"),
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "sample_app_http_request_duration_seconds",
    "HTTP request processing duration in seconds.",
    ("method", "route"),
)

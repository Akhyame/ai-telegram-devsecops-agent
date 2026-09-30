# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm@sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    SAMPLE_APP_ENVIRONMENT=production \
    SAMPLE_APP_LOG_LEVEL=INFO

WORKDIR /app

RUN groupadd --gid 10001 appgroup \
    && useradd \
        --uid 10001 \
        --gid appgroup \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        appuser

COPY pyproject.toml README.md ./
COPY agent ./agent
COPY api ./api
COPY bot ./bot
COPY deployment ./deployment
COPY gitlab_client ./gitlab_client
COPY policy_engine ./policy_engine
COPY sample_app ./sample_app

RUN python -m pip install .

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2).close()"]

CMD ["python", "-m", "uvicorn", "sample_app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
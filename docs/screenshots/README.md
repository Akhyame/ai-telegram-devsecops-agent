# Visual Evidence

This gallery contains the curated screenshots used to document the validated staging implementation.

## Architecture

![Architecture diagram](00_architecture_diagram.png)

High-level architecture showing Telegram interaction, RBAC/control, GitLab CI/CD and security stages, deterministic Security Gate enforcement, staging deployment, the Real FastAPI workload, and monitoring/alerting.

## Telegram Control

![Telegram help and status](01_telegram_help_status.png)

Role-based Telegram command surface and successful pipeline status.

## Agent CI/CD Pipeline

![Agent pipeline overview](02_agent_pipeline_overview.png)

Representative successful Agent pipeline showing quality, tests, security scans and build stages.

![Agent gate and deployment](03_agent_pipeline_gate_deploy.png)

Security Gate, staging validation and deployment stages.

## Deterministic Security Gate

![Security Gate ALLOW](04_security_gate_allow.png)

Security Gate evidence showing an `ALLOW` decision for the validated pipeline with zero blocking findings.

## Real FastAPI Integration

![Real FastAPI pipeline overview](05_real_fastapi_pipeline_overview.png)

Quality, tests, security scans and build stages for the separate Real FastAPI application.

![Real FastAPI gate and deployment](06_real_fastapi_pipeline_gate_deploy.png)

Security Gate, staging validation and deployment for the separate Real FastAPI application.

## Monitoring & Alerting

![Monitoring validation](07_monitoring_validation.png)

Prometheus and Alertmanager deployment validation, application target UP, internal monitoring network, and no host-published monitoring ports.

![Telegram FIRING and RESOLVED alerts](08_monitoring_firing_resolved_telegram.png)

Controlled staging outage producing a `FIRING` alert, followed by `RESOLVED` after service recovery.

## Final Runtime Validation

![Healthy staging services](09_staging_services_healthy.png)

Agent, monitoring and Real FastAPI staging services running with healthy application containers.

![Real FastAPI Swagger UI](10_real_fastapi_swagger_ui.png)

Swagger UI for the deployed Real FastAPI staging application through the controlled SSH tunnel.

> The simple `/health-check/` screenshot was intentionally omitted from this public gallery because the Docker health evidence and Swagger UI provide stronger visual proof.
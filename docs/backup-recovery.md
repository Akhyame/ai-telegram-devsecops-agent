# Backup and Recovery Runbook

## Purpose

This runbook defines the minimal backup and recovery model for the AI DevSecOps Agent staging platform.

The platform is recovered declaratively from trusted source control, immutable container image identity, protected CI/CD configuration, and securely re-provisioned credentials.

Production is intentionally unprovisioned and is outside the current recovery scope.

## Recovery Principles

1. Git is the authoritative source for application code and deployment configuration.
2. Recovery must use a known-good immutable commit SHA.
3. The deterministic Policy Engine remains the sole authorization authority after recovery.
4. Credentials must never be copied into the repository, backup archives, logs, or recovery evidence.
5. Plaintext `.env` files, API tokens, Telegram tokens, webhook secrets, monitoring receiver secrets, SSH private keys, and similar credentials are excluded from project backups.
6. Lost credentials are re-provisioned through approved protected configuration channels and rotated when compromise is suspected.
7. Monitoring failure or monitoring-state loss must never trigger a core application rollback.
8. Production must not be provisioned or deployed as part of staging recovery.

## Backup Classification

| Asset | Classification | Recovery source |
| --- | --- | --- |
| Application source | Required | Git repository |
| Deployment Compose files | Required | Git repository |
| Monitoring configuration | Required | Git repository |
| Alert rules | Required | Git repository |
| Python dependency pins | Required | Git repository |
| CI/CD definition | Required | Git repository |
| Application container image | Required | Registry using immutable commit identity |
| GitLab protected variables | Required configuration, secret values excluded from repository backup | Secure re-provisioning |
| Local `.env` | Never archive as project backup | Recreate securely from approved credential sources |
| SSH private keys | Never archive as project backup | Re-provision securely |
| `prometheus_config` volume | Reconstructable | `deployment/monitoring.sh` + tracked monitoring files |
| `alertmanager_config` volume | Reconstructable | `deployment/monitoring.sh` + tracked monitoring files |
| `prometheus_data` volume | Optional historical state | Clean recreation is acceptable for staging |
| `alertmanager_data` volume | Optional transient state | Clean recreation is acceptable for staging |

## Authoritative Tracked Recovery Files

The following files must remain available in source control:

- `.gitlab-ci.yml`
- `.env.example`
- `pyproject.toml`
- `deployment/compose.yml`
- `deployment/compose.staging.yml`
- `deployment/monitoring.sh`
- `monitoring/prometheus/prometheus.yml`
- `monitoring/prometheus/alerts.yml`
- `monitoring/alertmanager/alertmanager.yml`

The production Compose definition may remain tracked as configuration, but production remains intentionally unprovisioned.

## Recovery Scenarios

### Scenario 1 ? Application Containers Lost

1. Confirm the target environment is `staging`.
2. Select the last known-good commit SHA.
3. Confirm required protected staging credentials are provisioned without displaying their values.
4. Trigger the controlled staging deployment pipeline for the selected commit.
5. Require the deterministic security gate and deployment validation to pass.
6. Verify API and Bot containers are running.
7. Verify `/health/live` and `/health/ready`.
8. Confirm no production deployment job executed.

No Docker container filesystem is treated as authoritative state.

### Scenario 2 ? Monitoring Configuration Volumes Lost

The Prometheus and Alertmanager configuration volumes are reconstructable.

1. Restore or check out the known-good repository revision.
2. Use the tracked monitoring configuration and alert-rule files.
3. Run the normal controlled monitoring deployment path.
4. `deployment/monitoring.sh` provisions the configuration volumes.
5. Validate Prometheus configuration and alert rules.
6. Validate Alertmanager configuration.
7. Verify Prometheus and Alertmanager return to running state.

Do not manually restore old configuration files from an untrusted archive.

### Scenario 3 ? Monitoring Data Volumes Lost

`prometheus_data` contains historical metrics and `alertmanager_data` contains operational monitoring state.

For the current staging architecture, both may be recreated empty.

Expected consequence:

- historical Prometheus metrics may be lost;
- transient Alertmanager state may be lost;
- the core API, Telegram Bot, authorization model, CI/CD control plane, and deployment identity remain recoverable;
- alerting resumes after monitoring services restart and new data arrives.

Loss of monitoring history must not cause a core application rollback.

### Scenario 4 ? Runtime Credential Files Lost

Do not recover credentials from Git, logs, shell history, old build artifacts, or plaintext backup archives.

1. Re-provision required secrets through approved protected configuration channels.
2. Preserve existing credential separation:
   - read-only GitLab credential for read operations;
   - Bot-only GitLab write credential for controlled write actions;
   - webhook signing credential for API verification;
   - monitoring receiver credential for the internal receiver;
   - Telegram credential only where Telegram delivery is required.
3. Rotate credentials if loss may indicate exposure.
4. Rebuild runtime environment files without displaying secret values.
5. Redeploy staging through the controlled pipeline.

### Scenario 5 ? GitLab Runner Workspace Lost

GitLab Runner build directories are ephemeral and are not backup targets.

Recovery consists of:

1. providing a healthy authorized runner;
2. fetching the known-good commit from Git;
3. using pinned CI/runtime dependencies and immutable image identity;
4. executing the controlled staging pipeline.

The previous `/builds/...` working directory is not required.

## Recovery Validation Checklist

A staging recovery is accepted only when all applicable checks pass:

- repository revision matches the intended commit SHA;
- static/quality checks pass;
- security tests pass;
- full regression passes;
- security-gate evidence is valid;
- API health checks pass;
- Bot is running;
- Prometheus and Alertmanager are running when monitoring is included;
- runtime credentials are present but their values are not displayed;
- no secret appears in logs or recovery evidence;
- no production deployment occurred;
- the deterministic Policy Engine remains authoritative.

## Backup Operations Policy

The project does not require periodic plaintext backup of runtime environment files or Docker configuration volumes.

The minimal backup strategy is:

- preserve Git repository history and tracked configuration;
- preserve access to immutable registry images required by the selected recovery revision;
- maintain credentials through an approved secure credential-management process outside repository backups;
- optionally preserve monitoring history only when historical metrics become a business requirement.

If historical monitoring retention becomes mandatory in a future production deployment, Prometheus and Alertmanager data backup procedures must be designed separately with encryption, retention, restore testing, and access controls.

## Current Limitation

This runbook covers the validated staging architecture.

It does not claim full-site disaster recovery for GitLab itself, the Docker registry provider, external Telegram infrastructure, or a future production environment.

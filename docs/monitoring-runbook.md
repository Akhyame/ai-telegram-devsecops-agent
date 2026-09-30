# Monitoring Runbook

## 1. Purpose

This runbook documents the validated monitoring deployment, verification, alert handling, failure isolation, and recovery workflow for the AI DevSecOps Agent Controlled via Telegram.

The validated monitoring stack uses:

- Prometheus v3.13.2
- Alertmanager v0.33.1
- tracked Prometheus configuration
- tracked Prometheus alert rules
- tracked Alertmanager configuration
- an authenticated internal alert receiver
- outbound Telegram alert delivery
- an internal Docker monitoring network
- no host-published Prometheus or Alertmanager ports

Monitoring is operationally separate from core application rollback.

A monitoring failure must never trigger automatic rollback of a healthy application release.

---

## 2. Validated Monitoring Boundary

The validated live monitoring environment is staging.

The GitLab CI monitoring job is:

```text
deploy_staging_monitoring
```

It depends on:

```text
validate_staging_deployment
deploy_staging
```

Therefore monitoring deployment is downstream of an already validated staging application deployment.

The project does not claim a validated live production monitoring deployment.

---

## 3. Authoritative Monitoring Components

The primary monitoring implementation files are:

```text
deployment/monitoring.sh
deployment/compose.yml
deployment/compose.staging.yml
monitoring/prometheus/prometheus.yml
monitoring/prometheus/alerts.yml
monitoring/alertmanager/alertmanager.yml
sample_app/monitoring_alert_config.py
.gitlab-ci.yml
```

Related operational documentation:

```text
docs/deployment-runbook.md
docs/backup-recovery.md
docs/security-overview.md
docs/telegram-operations-guide.md
docs/installation-configuration.md
```

---

## 4. Monitoring Deployment Entry Point

The validated monitoring deployment path is GitLab CI.

The staging monitoring job invokes:

```text
sh deployment/monitoring.sh
```

The monitoring script is not a general-purpose interactive `start`, `stop`, or `status` CLI.

Its validated role is to:

- validate monitoring configuration,
- provision monitoring configuration volumes,
- stage the Alertmanager receiver credential safely,
- create or replace the required monitoring containers,
- validate Prometheus rules and configuration,
- validate Alertmanager configuration,
- verify readiness,
- verify network isolation,
- verify absence of host-published monitoring ports,
- verify that the sample application target is successfully scraped.

---

## 5. CI Dependency Chain

The validated staging monitoring chain is:

```text
security scanners
→ security_gate
→ validate_staging_deployment
→ deploy_staging
→ deploy_staging_monitoring
```

Monitoring therefore does not become a substitute for the Security Gate or core deployment validation.

The monitoring job must not be manually treated as proof that the application deployment itself was valid.

---

## 6. Required Monitoring Script Inputs

`deployment/monitoring.sh` requires:

```text
DEPLOYMENT_ENVIRONMENT
DEPLOYMENT_IMAGE_REPOSITORY
DEPLOYMENT_COMMIT_SHA
DEPLOYMENT_COMPOSE_OVERRIDE
DEPLOYMENT_API_ENV_FILE
DEPLOYMENT_BOT_ENV_FILE
```

Monitoring configuration paths default to:

```text
PROMETHEUS_CONFIG_PATH=monitoring/prometheus/prometheus.yml
PROMETHEUS_RULES_PATH=monitoring/prometheus/alerts.yml
ALERTMANAGER_CONFIG_PATH=monitoring/alertmanager/alertmanager.yml
```

The result file defaults to:

```text
monitoring-result.json
```

through:

```text
MONITORING_RESULT_PATH
```

These values are deployment inputs and configuration metadata.

Sensitive runtime values must not be printed into documentation, CI output, screenshots, or Telegram messages.

---

## 7. Environment and Compose Binding

The monitoring script accepts only the validated environment/override pairings:

```text
staging:deployment/compose.staging.yml
production:deployment/compose.production.yml
```

Any mismatched environment/Compose override fails.

Although the script contains both environment pairings, the validated CI monitoring deployment path is staging.

Production remains intentionally unprovisioned.

---

## 8. Remote Docker Target

The monitoring script sets:

```text
DOCKER_HOST=ssh://deployment-target
```

Monitoring containers and volumes are therefore managed on the authorized deployment target through the configured Docker-over-SSH context.

Do not open additional inbound ports merely to simplify monitoring administration.

---

## 9. Monitoring Compose Project

The monitoring script uses the environment-specific Compose project:

```text
ai-devsecops-<environment>
```

For staging:

```text
ai-devsecops-staging
```

Monitoring services are part of the same environment-specific Compose project while retaining network and rollback isolation requirements.

---

## 10. Configuration File Safety Checks

Before deployment, `monitoring.sh` validates the tracked monitoring configuration files.

It rejects a required configuration when:

- the file is missing,
- the path is a symbolic link,
- the file size cannot be parsed,
- the file exceeds the configured size limit.

The validated maximum size for each of the following files is:

```text
65536 bytes
```

Files checked include:

```text
monitoring/prometheus/prometheus.yml
monitoring/prometheus/alerts.yml
monitoring/alertmanager/alertmanager.yml
```

This limits configuration abuse and avoids blindly accepting unexpected filesystem objects.

---

## 11. Prometheus Configuration

The tracked Prometheus configuration uses:

```text
scrape_interval: 15s
evaluation_interval: 15s
```

Prometheus loads the tracked alert rules and uses Alertmanager for alert delivery.

The monitored application job is:

```text
sample-app
```

The target is:

```text
api:8000
```

This is an internal service-to-service target, not a public host endpoint.

---

## 12. Alertmanager Routing

The validated Alertmanager route sends alerts to:

```text
monitoring-webhook
```

Validated routing timing includes:

```text
group_wait: 30s
group_interval: 5m
repeat_interval: 4h
```

The webhook destination is internal:

```text
http://api:8000/internal/monitoring/alerts
```

Resolved notifications are enabled:

```text
send_resolved: true
```

The webhook receiver is authenticated through the application's internal monitoring receiver control.

---

## 13. Alertmanager Credential Handling

The Alertmanager receiver credential is obtained from the authorized runtime API environment file.

The deployment script does not intentionally echo the credential.

It stages the credential through a temporary file, applies restrictive file permissions, provisions the required Alertmanager configuration, and removes the temporary file during cleanup.

Operational rule:

Never inspect or paste the receiver credential value during normal monitoring validation.

Validate only its presence and the success/failure of the controlled provisioning path.

---

## 14. Temporary Credential Cleanup

The monitoring script registers cleanup handling for normal exit and termination signals.

Temporary Alertmanager receiver credential material is removed when cleanup runs.

Helper containers used for configuration provisioning are also cleaned up.

A failed provisioning attempt must not be followed by copying temporary credential contents into logs for debugging.

---

## 15. Prometheus Configuration Provisioning

The monitoring script provisions tracked Prometheus configuration into the runtime configuration volume.

Tracked source files include:

```text
monitoring/prometheus/prometheus.yml
monitoring/prometheus/alerts.yml
```

The generated runtime configuration volume is reconstructable.

It is not authoritative state.

Git-tracked configuration remains authoritative.

---

## 16. Prometheus Configuration Validation

Before accepting the monitoring deployment, the script validates:

- Prometheus alert rules,
- Prometheus main configuration.

The validation uses the pinned Prometheus runtime version:

```text
prom/prometheus:v3.13.2
```

Invalid rules or invalid Prometheus configuration cause monitoring deployment failure.

Do not bypass this validation by manually editing the runtime configuration volume.

---

## 17. Alertmanager Configuration Provisioning

The monitoring script provisions the tracked Alertmanager configuration into its runtime configuration volume.

The tracked source file is:

```text
monitoring/alertmanager/alertmanager.yml
```

The runtime configuration volume is reconstructable.

The tracked file plus controlled credential provisioning remain the authoritative recovery source.

---

## 18. Alertmanager Configuration Permissions

The provisioning path normalizes the generated Alertmanager configuration file permissions before runtime use.

The monitoring script validates configuration through the pinned Alertmanager runtime:

```text
prom/alertmanager:v0.33.1
```

A permission-normalization or configuration-validation failure causes the monitoring deployment to fail.

---

## 19. Monitoring Containers

The validated monitoring services are:

```text
prometheus
alertmanager
```

The script checks service container identity/count before accepting deployment.

Unexpected duplicate or missing monitoring containers are treated as invalid runtime state.

---

## 20. Alertmanager Readiness

After provisioning, the monitoring script waits for Alertmanager readiness.

It performs bounded readiness attempts rather than waiting indefinitely.

A monitoring deployment is not successful merely because the Alertmanager container exists.

Alertmanager must become ready.

---

## 21. Prometheus Readiness

The monitoring script similarly performs bounded Prometheus readiness attempts.

Prometheus must become ready before the monitoring deployment can pass.

A running but unready container is not considered valid monitoring.

---

## 22. No Host-Published Alertmanager Port

The script checks whether Alertmanager port:

```text
9093/tcp
```

is published on the Docker host.

The validated result is:

```text
ALERTMANAGER_HOST_PORT_PUBLISHED=false
```

Alertmanager must remain internal to the validated network boundary.

---

## 23. No Host-Published Prometheus Port

The script checks whether Prometheus port:

```text
9090/tcp
```

is published on the Docker host.

The validated result is:

```text
PROMETHEUS_HOST_PORT_PUBLISHED=false
```

Prometheus must remain internal to the validated monitoring boundary.

---

## 24. Internal Monitoring Network

The monitoring stack is attached to an internal Docker network.

The deployment script verifies that the monitoring network is internal.

The validated result is:

```text
MONITORING_NETWORK_INTERNAL=true
```

This prevents accidental host/network exposure of Prometheus and Alertmanager.

---

## 25. Prometheus Target Verification

Readiness alone is insufficient.

The monitoring script verifies that Prometheus can successfully scrape the application target.

The target is:

```text
api:8000
```

The validated result is:

```text
PROMETHEUS_TARGET_UP=true
```

A ready Prometheus instance with a down application target is not accepted as a successful monitoring deployment.

---

## 26. Successful Monitoring Result

A successful monitoring deployment reports:

```text
MONITORING_RESULT=deployed
PROMETHEUS_READY=true
PROMETHEUS_TARGET_UP=true
PROMETHEUS_HOST_PORT_PUBLISHED=false
ALERTMANAGER_READY=true
ALERTMANAGER_HOST_PORT_PUBLISHED=false
MONITORING_NETWORK_INTERNAL=true
```

The structured result file records:

```text
status
environment
target_commit_sha
```

The result metadata must not contain secret values.

---

## 27. Monitoring Failure Result

The script centralizes failure handling through the monitoring failure path.

A failed monitoring deployment reports:

```text
MONITORING_RESULT=failed
```

Monitoring failure must remain distinct from application deployment failure.

The operator must diagnose monitoring without automatically rolling back a healthy core application.

---

## 28. Validated Alert Rules

The monitoring configuration defines three application alerts.

### SampleAppUnavailable

Condition:

```text
up{job="sample-app"} == 0
```

Duration:

```text
2m
```

Severity:

```text
critical
```

Meaning:

Prometheus cannot scrape the sample application target for the sustained alert window.

### SampleAppHighServerErrors

Duration:

```text
5m
```

Severity:

```text
warning
```

Meaning:

HTTP 5xx response rate exceeds 5 percent during sustained request traffic.

### SampleAppHighLatency

Duration:

```text
10m
```

Severity:

```text
warning
```

Meaning:

Sustained HTTP request p95 latency exceeds one second.

---

## 29. Alert Lifecycle

Alertmanager sends firing alerts to the authenticated internal receiver.

Because:

```text
send_resolved: true
```

the receiver also receives resolved notifications.

Validated monitoring behavior includes:

- firing notification delivery,
- resolved notification delivery,
- deduplication behavior,
- minimized outbound Telegram alert content.

---

## 30. Telegram Alert Boundary

Telegram is used as the operator notification channel.

Alerts are outbound notifications from the application integration.

The monitoring stack does not require opening an inbound Telegram-facing service port.

Telegram notification delivery is not authoritative monitoring state.

Prometheus and Alertmanager remain the monitoring sources.

---

## 31. Alert Authentication Boundary

The Alertmanager webhook targets:

```text
http://api:8000/internal/monitoring/alerts
```

The receiver is protected by the configured monitoring receiver credential.

An unauthenticated or invalid alert request must not be accepted as trusted monitoring input.

Do not weaken receiver authentication to simplify alert testing.

---

## 32. Monitoring Deployment Procedure

### Step 1 — Validate the application deployment

Monitoring deployment should follow a successfully validated staging application deployment.

Confirm that:

```text
deploy_staging
```

has succeeded for the intended immutable SHA.

### Step 2 — Allow the monitoring CI job to run

The validated job is:

```text
deploy_staging_monitoring
```

Do not invoke an ad-hoc manual Prometheus container as a substitute.

### Step 3 — Validate configuration provisioning

The job must successfully validate and provision:

```text
prometheus.yml
alerts.yml
alertmanager.yml
```

### Step 4 — Validate Alertmanager readiness

Expected:

```text
ALERTMANAGER_READY=true
```

### Step 5 — Validate Prometheus readiness

Expected:

```text
PROMETHEUS_READY=true
```

### Step 6 — Validate application scraping

Expected:

```text
PROMETHEUS_TARGET_UP=true
```

### Step 7 — Validate network isolation

Expected:

```text
PROMETHEUS_HOST_PORT_PUBLISHED=false
ALERTMANAGER_HOST_PORT_PUBLISHED=false
MONITORING_NETWORK_INTERNAL=true
```

### Step 8 — Confirm monitoring result

Expected:

```text
MONITORING_RESULT=deployed
```

---

## 33. Post-Deployment Operational Check

After monitoring deployment, verify:

- Prometheus is running,
- Alertmanager is running,
- both are ready,
- the sample application target is UP,
- monitoring network remains internal,
- ports 9090 and 9093 remain unpublished on the host,
- Telegram alert delivery works when a validated test condition is used,
- resolved delivery works,
- deduplication remains effective.

Do not expose Prometheus or Alertmanager publicly for convenience.

---

## 34. Application Unavailable Alert Response

When:

```text
SampleAppUnavailable
```

fires:

1. confirm the alert is firing rather than resolved;
2. check `/status` through Telegram;
3. inspect bounded `/logs` if needed;
4. verify the application deployment job and immutable SHA;
5. verify API/Bot container health;
6. verify API readiness;
7. determine whether the problem is the application or the scrape path;
8. use the deployment or recovery runbook if the application itself is unhealthy.

Do not roll back solely because an alert fired without validating the application condition.

---

## 35. High Server Error Alert Response

When:

```text
SampleAppHighServerErrors
```

fires:

1. confirm sustained 5xx behavior;
2. inspect bounded application logs;
3. correlate the event with recent deployment activity;
4. use `/status` for current pipeline state;
5. verify whether the active immutable SHA is the intended release;
6. investigate the application before considering deployment recovery.

The warning alert is evidence for investigation, not automatic authorization to roll back.

---

## 36. High Latency Alert Response

When:

```text
SampleAppHighLatency
```

fires:

1. confirm the alert duration has been sustained;
2. inspect application health and current load;
3. inspect bounded logs;
4. correlate with deployment and runtime changes;
5. verify container health;
6. avoid restarting services blindly.

A latency warning alone must not trigger automatic rollback.

---

## 37. Resolved Alert Handling

When a resolved notification arrives:

1. verify the condition actually returned to normal;
2. confirm the underlying service is healthy;
3. record the recovery context if the event is operationally significant;
4. avoid starting a second remediation action for an already resolved condition.

Resolved notifications are part of the validated alert lifecycle.

---

## 38. Deduplication

Alert delivery is designed to avoid unnecessary repeated Telegram notifications for the same state.

Operators should not treat a lack of repeated identical notifications as proof that monitoring stopped.

Check monitoring state directly when needed.

---

## 39. Monitoring Failure During Deployment

If:

```text
deploy_staging_monitoring
```

fails after a successful core staging deployment:

- the application deployment and monitoring deployment must be evaluated separately;
- do not automatically roll back the healthy application;
- inspect the monitoring job;
- identify whether the failure is configuration, provisioning, readiness, network, or scrape related;
- recover monitoring independently.

This is a core project invariant.

---

## 40. Prometheus Configuration Failure

If Prometheus configuration validation fails:

1. do not edit the runtime volume manually;
2. inspect the tracked configuration change;
3. correct `monitoring/prometheus/prometheus.yml` or the related tracked rule file;
4. commit the correction;
5. run the controlled CI path again.

Git-tracked configuration is authoritative.

---

## 41. Prometheus Rule Validation Failure

If alert-rule validation fails:

1. inspect `monitoring/prometheus/alerts.yml`;
2. correct syntax or expression configuration in source control;
3. do not patch the generated volume directly;
4. commit and rerun the validated CI path.

---

## 42. Alertmanager Configuration Failure

If Alertmanager configuration validation fails:

1. inspect the tracked `alertmanager.yml`;
2. do not print the receiver credential;
3. verify configuration structure without exposing secrets;
4. correct the tracked file when required;
5. rerun the controlled monitoring deployment.

---

## 43. Alertmanager Credential Provisioning Failure

If receiver credential provisioning fails:

1. do not print the credential value;
2. validate only the existence and secure provisioning of the runtime API environment file;
3. verify the required variable is configured through the secure environment-management path;
4. do not recover the value from Git, logs, shell history, screenshots, or old artifacts;
5. reprovision the credential securely if it is lost or suspected compromised.

Use `docs/backup-recovery.md` for credential recovery principles.

---

## 44. Alertmanager Not Ready

If Alertmanager does not become ready:

1. inspect bounded container status/log metadata;
2. verify configuration validation succeeded;
3. verify the Alertmanager configuration volume exists;
4. verify network attachment;
5. avoid publishing port 9093 to the host as a debugging shortcut;
6. recover the monitoring service independently.

---

## 45. Prometheus Not Ready

If Prometheus does not become ready:

1. verify configuration validation succeeded;
2. verify alert rules validation succeeded;
3. verify the Prometheus configuration volume;
4. verify monitoring network attachment;
5. inspect bounded status/log metadata;
6. do not publish port 9090 to the host for convenience.

---

## 46. Prometheus Target Down

If:

```text
PROMETHEUS_TARGET_UP=false
```

or the monitoring deployment fails its scrape validation:

1. confirm the API application container is healthy;
2. confirm the internal service name remains `api`;
3. confirm the application listens on container port 8000;
4. confirm the monitoring network connectivity;
5. determine whether the fault is application availability or monitoring connectivity;
6. avoid changing alert rules merely to hide the failure.

---

## 47. Unexpected Host Port Exposure

If Prometheus or Alertmanager is found with a host-published port:

1. treat the monitoring deployment as invalid;
2. inspect Compose/runtime configuration;
3. remove the unintended host publishing through the controlled configuration path;
4. redeploy monitoring;
5. verify:

```text
PROMETHEUS_HOST_PORT_PUBLISHED=false
ALERTMANAGER_HOST_PORT_PUBLISHED=false
```

Do not accept public monitoring exposure as a temporary normal state.

---

## 48. Monitoring Network Not Internal

If:

```text
MONITORING_NETWORK_INTERNAL=false
```

the monitoring deployment must be treated as invalid.

Restore the tracked internal-network configuration and redeploy through the controlled path.

Do not weaken the network boundary to solve temporary connectivity issues.

---

## 49. Monitoring Configuration Volume Loss

The monitoring configuration volumes are reconstructable.

Relevant volumes include:

```text
prometheus_config
alertmanager_config
```

Recovery source:

```text
deployment/monitoring.sh
tracked monitoring configuration files
```

Use the recovery procedure documented in:

```text
docs/backup-recovery.md
```

Do not restore configuration from an untrusted archive.

---

## 50. Monitoring Data Volume Loss

Monitoring data volumes include:

```text
prometheus_data
alertmanager_data
```

For the validated staging environment, these are not authoritative application state.

Loss may result in:

- lost historical Prometheus metrics,
- lost transient Alertmanager operational state.

Clean recreation is acceptable in the validated staging scope.

Loss of monitoring history must not cause core application rollback.

---

## 51. Monitoring Recovery Procedure

When monitoring state must be reconstructed:

1. restore or check out the known-good repository revision;
2. confirm the intended immutable application SHA;
3. confirm the core staging application is healthy;
4. securely reprovision required runtime credentials if needed;
5. run the controlled monitoring deployment path;
6. validate Prometheus configuration and rules;
7. validate Alertmanager configuration;
8. validate Alertmanager readiness;
9. validate Prometheus readiness;
10. validate application target UP;
11. validate no host-published monitoring ports;
12. validate the monitoring network is internal;
13. test firing and resolved Telegram delivery when appropriate.

---

## 52. Monitoring and Core Rollback Separation

This invariant is mandatory:

```text
Monitoring failure must never automatically trigger core application rollback.
```

Examples that must remain monitoring-only incidents unless independent application evidence proves otherwise:

- lost Prometheus configuration volume,
- lost Prometheus historical data,
- Alertmanager configuration failure,
- failed Telegram alert delivery,
- Alertmanager readiness failure,
- Prometheus readiness failure caused by monitoring configuration,
- monitoring network reconstruction.

---

## 53. Telegram Monitoring Operations

Telegram operational commands useful during monitoring incidents include:

```text
/status
/logs
/explain
```

Security explanations may use:

```text
/explain security
/explain_security
```

Telegram logs are bounded and redacted.

Do not request or paste raw monitoring credentials.

AI explanations are diagnostic only.

---

## 54. Monitoring Evidence Checklist

For validated monitoring deployment evidence, retain sanitized metadata showing:

- GitLab pipeline ID,
- target immutable commit SHA,
- `deploy_staging` success,
- `deploy_staging_monitoring` status,
- `MONITORING_RESULT`,
- `PROMETHEUS_READY`,
- `PROMETHEUS_TARGET_UP`,
- `PROMETHEUS_HOST_PORT_PUBLISHED`,
- `ALERTMANAGER_READY`,
- `ALERTMANAGER_HOST_PORT_PUBLISHED`,
- `MONITORING_NETWORK_INTERNAL`,
- alert firing/resolved validation when tested,
- absence of production runtime changes.

Never retain receiver credential values as evidence.

---

## 55. Prohibited Monitoring Shortcuts

Do not:

- publish Prometheus 9090 to the host,
- publish Alertmanager 9093 to the host,
- disable internal-network isolation,
- remove alert receiver authentication,
- paste the receiver token into CI logs,
- manually patch generated configuration volumes as the source of truth,
- suppress an alert solely to hide an application problem,
- interpret AI output as monitoring authority,
- automatically roll back the core application because monitoring failed,
- provision production monitoring only for demonstration.

---

## 56. Production Monitoring Boundary

The monitoring script recognizes the production Compose pairing as a valid configuration path.

However, the validated CI monitoring deployment described by this runbook is staging:

```text
deploy_staging_monitoring
```

Production remains intentionally unprovisioned.

A future production monitoring design requires separate validation for:

- production infrastructure,
- credentials,
- retention requirements,
- availability requirements,
- data backup,
- Alertmanager routing,
- access controls,
- production network architecture,
- restore testing.

This runbook is not production monitoring certification.

---

## 57. Final Monitoring Validation Checklist

Monitoring is considered successfully validated when all applicable conditions are true:

- core staging deployment is valid;
- monitoring deployment runs through the controlled CI path;
- tracked Prometheus configuration is accepted;
- tracked alert rules are accepted;
- tracked Alertmanager configuration is accepted;
- receiver credential provisioning succeeds without secret exposure;
- Alertmanager is ready;
- Prometheus is ready;
- Prometheus can scrape `api:8000`;
- Prometheus port 9090 is not host-published;
- Alertmanager port 9093 is not host-published;
- monitoring network is internal;
- firing alerts can reach the authenticated receiver;
- resolved notifications are supported;
- Telegram alert content remains minimized;
- monitoring failure remains isolated from core rollback;
- production remains untouched.

---

## 58. Related Documentation

- [`deployment-runbook.md`](deployment-runbook.md) — staging deployment, verification, rollback, and production boundary.
- [`backup-recovery.md`](backup-recovery.md) — recovery scenarios for application and monitoring state.
- [`security-overview.md`](security-overview.md) — consolidated security architecture and controls.
- [`telegram-operations-guide.md`](telegram-operations-guide.md) — Telegram operations, RBAC, and bounded logs.
- [`installation-configuration.md`](installation-configuration.md) — secure installation and configuration.
- [`../README.md`](../README.md) — project overview and documentation index.

---

## 59. Current Validated Boundary

This runbook documents the validated academic/lab monitoring architecture for staging.

The operational rule is:

```text
Validate the application first.
Deploy monitoring through CI.
Keep Prometheus and Alertmanager internal.
Treat monitoring failures independently from application rollback.
Production only after separate provisioning and validation.
```

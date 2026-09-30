# Security Overview

## 1. Purpose

This document is the security entry point for the AI DevSecOps Agent Controlled via Telegram.

It consolidates the validated security architecture, control model, operational boundaries, and supporting documentation without replacing the detailed threat model or recovery procedures.

The validated academic/lab implementation follows these core principles:

- deny by default,
- deterministic authorization,
- least privilege,
- separation of read and write credentials,
- one-time confirmation for mutating actions,
- replay resistance,
- bounded and redacted output,
- fail-closed security decisions,
- immutable deployment identity,
- hardened container runtime,
- monitoring isolation,
- non-authoritative AI,
- staging-first validation,
- intentionally unprovisioned production.

---

## 2. Security Authority

The deterministic Policy Engine and Security Gate are the sole authorities for security decisions.

The system blocks:

- `HIGH` findings,
- `CRITICAL` findings,
- `UNKNOWN` severities.

Malformed or invalid security input is handled fail-closed.

AI output cannot:

- authorize a pipeline,
- authorize a deployment,
- override a Security Gate decision,
- downgrade a finding,
- modify RBAC,
- bypass confirmation,
- remediate independently.

The AI layer is explanatory only.

---

## 3. Trust Boundaries

The validated threat model defines the following principal trust boundaries:

1. Telegram User → Bot
2. Bot → GitLab
3. AI Boundary
4. Policy Engine
5. GitLab Webhook
6. CI/CD → Docker Staging
7. Monitoring
8. Credentials and Recovery

Detailed threats, controls, residual risks, and production limitations are documented in:

- [`threat-model.md`](threat-model.md)

---

## 4. Telegram Authorization and RBAC

Telegram access is deny-by-default.

Authorization is based on configured Telegram user IDs and deterministic role resolution.

Validated roles:

### Viewer

Permitted read-only commands:

- `/start`
- `/help`
- `/status`

### Operator

Inherits Viewer permissions and adds:

- `/logs`
- `/explain`
- `/explain security`
- `/explain_security`
- `/run_pipeline`
- `/retry_pipeline`
- `/scan`

### Admin

Inherits Operator permissions and adds:

- `/cancel_pipeline`
- `/deploy staging`
- `/deploy_staging`

Detailed operational behavior is documented in:

- [`telegram-operations-guide.md`](telegram-operations-guide.md)

---

## 5. Mutating Action Confirmation

Sensitive Telegram actions require deterministic confirmation.

Validated properties include:

- one-time confirmation,
- 120-second TTL,
- replay resistance,
- target binding,
- atomic confirmation consumption,
- bounded pending-confirmation storage,
- expired confirmation pruning.

Protected actions include:

- pipeline launch,
- pipeline retry,
- pipeline cancellation,
- security scan,
- deployment.

A confirmation cannot be reused as a general authorization token.

---

## 6. GitLab Credential Separation

The implementation separates GitLab read and write responsibilities.

Primary current variables include:

- `GITLAB_API_URL`
- `GITLAB_API_TOKEN`
- `GITLAB_WRITE_API_TOKEN`
- `GITLAB_PROJECT_ID`
- `GITLAB_DEFAULT_REF`

The read path and write path use separate configuration objects and credentials.

This limits the blast radius of a read-token compromise and prevents routine status/log retrieval from requiring write privilege.

Legacy template fields such as `GITLAB_URL` and `GITLAB_TOKEN` are not the primary current Python runtime interface.

Configuration details are documented in:

- [`installation-configuration.md`](installation-configuration.md)

---

## 7. Server-Side Target Control

Telegram users cannot freely select arbitrary privileged targets.

Validated controls include:

- `/run_pipeline` uses the configured allowlisted project/ref,
- `/scan` uses one fixed predefined full security scan profile,
- `/scan` rejects arguments,
- `/retry_pipeline` selects the latest eligible pipeline server-side,
- `/cancel_pipeline` selects the latest eligible pipeline server-side,
- pipeline IDs are not supplied manually by Telegram users,
- Telegram deployment accepts only the allowlisted `staging` environment; production input is rejected.

This reduces target-substitution and command-injection risk.

---

## 8. CI Security Controls

The GitLab CI pipeline implements multiple independent security layers.

### Secret Detection

Job:

```text
secret_scan
```

Purpose:

- scan Git history for leaked secrets,
- block when confirmed secret findings are detected,
- publish a structured report without intentionally exposing secret values.

Validated scanner:

- Gitleaks v8.30.1

### Dependency Vulnerability Scanning

Job:

```text
dependency_scan
```

Purpose:

- audit resolved Python dependencies for known vulnerabilities.

Validated scanner:

- pip-audit v2.10.1

### Static Application Security Testing

Job:

```text
sast_scan
```

Purpose:

- scan tracked source/configuration files with Semgrep rules.

Validated scanner:

- Semgrep v1.174.0

### Filesystem and Configuration Scanning

Job:

```text
trivy_filesystem_scan
```

Purpose:

- scan the repository for vulnerabilities and configuration issues.

Validated scanner:

- Trivy v0.74.0

### Container Image Scanning

Job:

```text
trivy_image_scan
```

Purpose:

- scan the immutable commit-SHA container image,
- evaluate OS and Python-package vulnerabilities,
- evaluate image configuration,
- fail on configured blocking conditions.

### Deterministic Security Gate

Job:

```text
security_gate
```

Purpose:

- normalize scanner reports,
- evaluate them using the deterministic Policy Engine,
- produce an `ALLOW` or `BLOCK` decision.

The Security Gate is not AI-controlled.

---

## 9. Security Gate Policy

Normalized severities include:

- `INFO`
- `LOW`
- `MEDIUM`
- `HIGH`
- `CRITICAL`
- `UNKNOWN`

The validated policy blocks:

```text
HIGH
CRITICAL
UNKNOWN
```

Unknown or malformed security states must not silently pass.

The policy is deterministic and scanner-independent after normalization.

---

## 10. Deployment Security

Deployment is gated by CI/CD and deterministic validation.

The validated dependency chain is:

```text
security scanners
→ security_gate
→ security-gate-result.json
→ deployment validation
→ deployment job
```

The deployment path uses immutable commit/image identity.

Telegram confirmation does not bypass:

- GitLab CI rules,
- the Security Gate,
- deployment validation,
- environment provisioning requirements.

---

## 11. Staging Boundary

Staging is the validated deployment environment.

Validated controls include:

- protected target configuration,
- immutable image identity,
- deterministic Security Gate validation,
- Telegram Admin authorization for deploy actions,
- one-time deployment confirmation,
- hardened Docker runtime,
- monitoring isolated from rollback behavior.

The current validated runtime is a lab/staging environment, not a production certification.

---

## 12. Production Boundary

Telegram production deployment command paths are disabled. Production-aware CI and deployment definitions remain tracked for environment separation.

However, production is intentionally unprovisioned in the validated environment.

Therefore:

- production credentials are absent,
- no live production deployment is claimed,
- production must not be provisioned merely for demonstration,
- production requires a separate design, credential lifecycle, validation process, and threat-model review.

This documentation must not be interpreted as production certification.

---

## 13. Runtime Hardening

The validated Docker runtime applies defense-in-depth controls including:

- non-root execution,
- read-only root filesystem,
- dropped Linux capabilities,
- `no-new-privileges`,
- health checks,
- bounded logging,
- minimized service exposure.

The staging API is exposed only through the validated loopback binding rather than an unnecessary public listener.

Runtime hardening is part of the security boundary and must not be relaxed for convenience.

---

## 14. Log and Output Safety

Telegram log retrieval is bounded and sanitized.

Validated `/logs` controls include:

- maximum 20 considered jobs,
- maximum 262,144 bytes of GitLab trace input,
- maximum 40 rendered lines,
- maximum 3,000 rendered characters,
- sensitive-pattern redaction,
- explicit truncation indication.

AI explanations also operate on normalized and bounded evidence.

Raw privileged traces and credentials must never be copied into Telegram for troubleshooting.

---

## 15. Webhook Security

GitLab webhook handling is designed to fail closed.

Validated controls include:

- signed webhook verification,
- fixed project boundary,
- normalized event handling,
- replay protection,
- minimized trusted input surface.

A forged or invalid webhook must not be accepted as authoritative pipeline state.

---

## 16. Monitoring Security

The validated monitoring stack uses:

- Prometheus v3.13.2,
- Alertmanager v0.33.1,
- authenticated internal alert receiver handling,
- outbound Telegram notification delivery,
- internal monitoring networking,
- no unnecessary host exposure for Prometheus or Alertmanager.

Monitoring is operationally independent from core rollback behavior.

A monitoring or alert-delivery failure must not trigger automatic core application rollback.

---

## 17. Secret Management

Secrets must not be committed to Git.

Validated repository safeguards include:

- local `.env` is not tracked,
- `.env.example` is tracked as the configuration template,
- no tracked sensitive filename was present in the packaging baseline,
- documentation avoids real credential values,
- CI includes secret scanning,
- secret values are excluded or redacted from controlled output where applicable.

Sensitive values include, among others:

- Telegram bot token,
- GitLab API tokens,
- GitLab write token,
- webhook signing token,
- Alertmanager receiver token,
- private SSH keys.

Never paste these values into documentation, Telegram messages, CI logs, screenshots, or troubleshooting output.

---

## 18. Backup and Recovery Security

Backup and recovery procedures are documented separately:

- [`backup-recovery.md`](backup-recovery.md)

Security principles include:

- do not store plaintext secrets in project backups,
- restore configuration and service state using controlled procedures,
- preserve immutable deployment identity,
- validate service health after recovery,
- treat monitoring recovery separately from core application rollback,
- keep production outside the validated recovery scope until separately provisioned.

---

## 19. Auditability

Security-sensitive operations generate controlled audit metadata.

Audited areas include:

- Telegram mutating actions,
- confirmation lifecycle events,
- AI explanation requests and outcomes,
- failure states.

Audit data must remain metadata-focused.

It must not include raw secrets or unnecessary sensitive payloads.

---

## 20. Rate Limiting and Bounded State

The bot includes bounded and rate-limited operational paths.

Security objectives include:

- prevent unbounded request amplification,
- limit pending confirmation state,
- limit external API pressure,
- reduce abuse of Telegram-triggered GitLab actions,
- preserve predictable failure behavior.

Rate limiting complements RBAC; it does not replace authorization.

---

## 21. Failure Handling

The security architecture favors static, minimized failure messages.

Internal errors should not expose:

- credentials,
- request headers,
- raw tokens,
- unrestricted GitLab responses,
- internal exception details unnecessary for the user.

Security-relevant failures must preserve fail-closed behavior.

---

## 22. Security Invariants

The following invariants define the validated security posture:

1. The Policy Engine is deterministic and authoritative.
2. AI cannot authorize, deploy, remediate, or override security decisions.
3. Invalid or unauthorized Telegram identities fail closed.
4. RBAC remains deterministic.
5. Privileged confirmations remain one-time and replay-resistant.
6. High, critical, and unknown findings cannot silently pass the Security Gate.
7. GitLab read and write responsibilities remain separated.
8. Deployment uses validated immutable identity.
9. Secrets are not committed to Git.
10. Controlled logs remain redacted and bounded.
11. Monitoring failure does not trigger core application rollback.
12. Production remains unprovisioned until separately designed and validated.

---

## 23. Residual Risk

The threat model explicitly recognizes residual risk.

Examples include:

- compromise of an authorized Telegram account,
- compromise of a GitLab Maintainer account,
- compromise of the staging Docker or Runner host,
- inaccurate AI explanations,
- outages affecting GitLab, Telegram, registry, or AI services.

These residual risks do not grant AI authorization authority and do not weaken the deterministic Security Gate.

See:

- [`threat-model.md`](threat-model.md)

---

## 24. Security Documentation Map

| Document | Purpose |
|---|---|
| [`security-overview.md`](security-overview.md) | Entry point for the validated security architecture and controls |
| [`threat-model.md`](threat-model.md) | Trust boundaries, threat scenarios, controls, residual risks, and production limitations |
| [`backup-recovery.md`](backup-recovery.md) | Backup, restore, recovery, and rollback security procedures |
| [`installation-configuration.md`](installation-configuration.md) | Secure installation, environment variables, GitLab credential separation, and configuration |
| [`telegram-operations-guide.md`](telegram-operations-guide.md) | Telegram RBAC, commands, confirmations, and safe operator/admin workflows |
| [`../README.md`](../README.md) | Project architecture, features, deployment model, and documentation index |

---

## 25. Source Security Components

Key implementation components include:

```text
bot/rbac.py
bot/action_confirmation.py
bot/action_audit.py
bot/ai_audit.py
bot/gitlab_logs.py
policy_engine/evaluator.py
policy_engine/config.py
policy_engine/parsers/
deployment/ci_gate.py
deployment/config.py
sample_app/webhook_config.py
sample_app/monitoring_alert_config.py
monitoring/prometheus/
monitoring/alertmanager/
.gitlab-ci.yml
.gitleaks.toml
security-policy.toml
```

These source files remain authoritative for implemented behavior.

Documentation must be updated if the underlying security behavior changes.

---

## 26. Validation Status

At the time this security package was prepared:

- repository cleanup had been validated,
- the final README had been validated,
- installation and configuration documentation had been validated,
- Telegram operations documentation had been validated,
- the final threat model was structurally complete,
- backup and recovery documentation covered backup, restore, recovery, configuration, secrets, Docker, monitoring, rollback, and production boundaries,
- CI security controls were present,
- runtime hardening signals were present,
- local `.env` was not tracked,
- production remained intentionally unprovisioned.

This package documents the validated academic/lab security posture and is not a production certification.

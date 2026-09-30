# Telegram Operations Guide

## 1. Purpose

This guide documents how authorized users operate the AI DevSecOps Agent through Telegram in the validated academic/lab environment.

The operational model preserves deterministic RBAC, deny-by-default authorization, server-selected or allowlisted GitLab targets, one-time replay-resistant confirmations, bounded and redacted output, deterministic Security Gate authority, and non-authoritative AI explanations.

Telegram deployment is staging-only. Production deployment commands are disabled, while production-aware CI definitions remain tracked but unprovisioned.

---

## 2. Roles and Permissions

### Viewer

Viewer commands:

- `/start`
- `/help`
- `/status`

### Operator

Operator inherits Viewer permissions and can also use:

- `/logs`
- `/explain`
- `/explain security`
- `/explain_security`
- `/run_pipeline`
- `/retry_pipeline`
- `/scan`

### Admin

Admin inherits Operator permissions and can also use:

- `/cancel_pipeline`
- `/deploy staging`
- `/deploy_staging`

Telegram user IDs are controlled through `TELEGRAM_ALLOWED_USER_IDS`, `TELEGRAM_OPERATOR_USER_IDS`, and `TELEGRAM_ADMIN_USER_IDS`. A user must first be in the allowed-user set; role elevation is then resolved deterministically.

---

## 3. Command Matrix

| Command | Minimum role | Purpose | Confirmation |
|---|---|---|---|
| `/start` | Viewer | Confirm bot availability | No |
| `/help` | Viewer | Show available commands | No |
| `/status` | Viewer | Show latest validated GitLab pipeline summary | No |
| `/logs` | Operator | Show one sanitized, bounded GitLab job log | No |
| `/explain` | Operator | Explain latest failed pipeline | No |
| `/explain security` | Operator | Explain latest Security Gate result | No |
| `/explain_security` | Operator | Alias for security explanation | No |
| `/run_pipeline` | Operator | Launch allowlisted GitLab pipeline/ref | Yes |
| `/retry_pipeline` | Operator | Retry latest eligible server-selected pipeline | Yes |
| `/scan` | Operator | Launch fixed full security scan profile | Yes |
| `/cancel_pipeline` | Admin | Cancel latest eligible server-selected pipeline | Yes |
| `/deploy staging` | Admin | Request staging deployment | Yes |
| `/deploy_staging` | Admin | Fixed staging deployment alias | Yes |

---

## 4. Read-Only Commands

### `/start`

```text
/start
```

Confirms the secure DevSecOps control bot is reachable and directs the user to `/help`.

### `/help`

```text
/help
```

Shows available commands by privilege level. The validated deployment command is `/deploy_staging`; the generic `/deploy staging` form is also registered. Production deployment is not exposed through Telegram.

### `/status`

```text
/status
```

Minimum role: Viewer.

Retrieves the latest GitLab pipeline through the read-only integration and returns only validated non-sensitive fields. If GitLab status retrieval is unavailable, the bot returns a static safe failure message instead of a raw internal exception.

### `/logs`

```text
/logs
```

Minimum role: Operator.

Returns one sanitized and bounded GitLab job trace for troubleshooting.

Validated limits:

- maximum pipeline jobs considered: **20**,
- maximum GitLab trace input: **262,144 bytes**,
- maximum rendered lines: **40**,
- maximum rendered output: **3,000 characters**,
- sensitive patterns are redacted before Telegram output,
- truncation is explicitly indicated.

This command is read-only and is not unrestricted GitLab trace access.

---

## 5. AI Explanation Commands

The AI layer is explanatory only. It cannot authorize, approve, override, or bypass RBAC, confirmation, GitLab CI/CD, deployment validation, or the deterministic Security Gate.

### `/explain`

```text
/explain
```

Minimum role: Operator.

Retrieves the latest failed job through the controlled GitLab read path, normalizes the failure, and requests a bounded local-AI explanation. If AI is unavailable, deterministic fallback metadata is returned where possible.

### `/explain security`

```text
/explain security
```

Explains the latest normalized Security Gate result.

### `/explain_security`

```text
/explain_security
```

Standalone equivalent of `/explain security`.

The deterministic Security Gate remains authoritative regardless of AI wording.

---

## 6. `/run_pipeline`

```text
/run_pipeline
```

Minimum role: Operator.

Purpose: launch the configured allowlisted GitLab pipeline/ref.

The user does not supply an arbitrary ref or pipeline ID.

Flow:

1. authorization is checked,
2. the fixed allowed target is prepared,
3. a fresh confirmation is issued,
4. Telegram shows **Confirm pipeline launch**,
5. the user must confirm within **120 seconds**,
6. the confirmation is consumed exactly once,
7. one pipeline launch request is sent,
8. a minimized acceptance response is returned.

Expired, invalid, or reused confirmations are rejected.

---

## 7. `/scan`

```text
/scan
```

Minimum role: Operator.

Launches the predefined full GitLab security scan profile.

Arguments are not accepted. For example, this is invalid:

```text
/scan sast
```

Flow:

1. authorization is checked,
2. the fixed project/ref scan target is built,
3. a fresh one-time confirmation is issued,
4. Telegram shows **Confirm security scan**,
5. the user confirms within **120 seconds**,
6. the predefined scan is launched exactly once.

The user cannot select an arbitrary scanner profile from Telegram.

---

## 8. `/retry_pipeline`

```text
/retry_pipeline
```

Minimum role: Operator.

Arguments are not accepted. The user does not enter a pipeline ID.

The bot resolves the latest pipeline server-side and allows retry only when its status is:

- `failed`, or
- `canceled`.

The confirmation is bound to that exact server-selected pipeline. If no eligible pipeline exists, the action is rejected with a safe static response.

---

## 9. `/cancel_pipeline`

```text
/cancel_pipeline
```

Minimum role: Admin.

Arguments are not accepted. The user cannot choose an arbitrary pipeline ID.

The latest server-selected pipeline is cancel-eligible when its status is one of:

- `created`,
- `waiting_for_resource`,
- `preparing`,
- `waiting_for_callback`,
- `pending`,
- `running`,
- `manual`,
- `scheduled`.

The confirmation binds the action to the exact pipeline target and is consumed exactly once.

---

## 10. Confirmation Security

Mutating Telegram actions use a shared deterministic confirmation mechanism.

Validated properties:

- confirmation TTL: **120 seconds**,
- one-time consumption,
- replay resistance,
- target/action binding,
- token-digest based state,
- bounded pending-confirmation storage,
- expired entries are pruned.

Protected actions include:

- pipeline launch,
- pipeline retry,
- pipeline cancellation,
- security scan,
- deployment.

If a confirmation expires or has already been consumed, request the original command again.

---

## 11. Deployment Commands

Deployment is Admin-only.

Registered forms:

```text
/deploy staging
/deploy_staging
```

Only the exact `staging` environment is accepted by the generic command. The `/deploy_staging` alias calls the same deployment path with a fixed staging environment.

### Recommended staging command

```text
/deploy_staging
```

Equivalent generic form:

```text
/deploy staging
```

Flow:

1. Admin authorization is checked,
2. the environment is allowlist-validated,
3. the project/ref/environment target is built,
4. an environment-bound one-time confirmation is issued,
5. Telegram shows **Confirm deployment**,
6. the user confirms within **120 seconds**,
7. the confirmation is consumed once,
8. the GitLab deployment pipeline request is submitted,
9. GitLab CI/CD and the Security Gate remain authoritative.

Telegram confirmation never bypasses the Security Gate.

---

## 12. Production Boundary

Telegram production deployment is disabled.

The generic `/deploy` handler accepts only the `staging` environment, and no production deployment alias is registered.

Production-aware CI and deployment definitions remain tracked for environment separation, but production infrastructure is intentionally unprovisioned and no live production deployment is claimed.

Any future production rollout requires a separately approved design, credential lifecycle, provisioning process, validation plan, and threat-model review.

---

## 13. Security Gate Authority

The deterministic Security Gate is the sole authority for security decisions.

The Telegram bot may launch approved requests, display normalized evidence, and request explanations. It may not:

- downgrade findings,
- ignore `HIGH`,
- ignore `CRITICAL`,
- treat `UNKNOWN` as safe,
- override a `BLOCK`,
- force deployment after a blocked gate.

AI output is never an authorization decision.

---

## 14. Recommended Operator Workflow

Check the current state:

```text
/status
```

Launch a new allowlisted pipeline when needed:

```text
/run_pipeline
```

Confirm within 120 seconds, then monitor:

```text
/status
```

For bounded troubleshooting:

```text
/logs
```

For the latest failed pipeline explanation:

```text
/explain
```

For a fresh full security scan:

```text
/scan
```

For the latest Security Gate explanation:

```text
/explain_security
```

If the latest pipeline is failed or canceled and should be retried:

```text
/retry_pipeline
```

---

## 15. Recommended Admin Workflow

Admin inherits the Operator workflow.

To cancel the latest eligible pipeline:

```text
/cancel_pipeline
```

To deploy to validated staging:

```text
/deploy_staging
```

or:

```text
/deploy staging
```

Production deployment is not exposed through Telegram; production-aware CI definitions remain tracked but intentionally unprovisioned.

---

## 16. What Users Must Not Do

Do not:

- share Telegram bot tokens,
- share GitLab API tokens,
- paste secrets into Telegram commands,
- pass arbitrary scan profiles,
- pass arbitrary pipeline IDs,
- reuse old confirmation buttons,
- treat AI output as authorization,
- treat `/logs` as unrestricted trace access,
- bypass GitLab CI/CD or the Security Gate,
- claim a live production deployment in the current validated environment.

---

## 17. Common Operational Conditions

### Invalid or expired confirmation

Run the original command again and use the fresh confirmation button.

### No eligible pipeline

Use `/status` to inspect the latest pipeline state. Retry or cancellation is only allowed for validated status sets.

### GitLab unavailable

The bot returns minimized failure messages instead of raw internal exceptions. Troubleshoot GitLab connectivity without exposing credentials or weakening authentication.

### AI unavailable

Rely on deterministic pipeline/Security Gate metadata. AI unavailability is never a reason to bypass security controls.

---

## 18. Monitoring and Notifications

The validated environment includes Prometheus and Alertmanager with authenticated outbound Telegram notifications.

Monitoring notifications complement operational commands but do not authorize any mutating action.

Monitoring failure must not automatically trigger core application rollback.

---

## 19. Auditability

Mutating Telegram operations generate controlled audit events for requested, confirmed, and failed actions. Audit records must remain metadata-focused and must not expose secret values.

AI interactions also use bounded audit events.

---

## 20. Quick Reference

### Viewer

```text
/start
/help
/status
```

### Operator

```text
/logs
/explain
/explain security
/explain_security
/run_pipeline
/retry_pipeline
/scan
```

### Admin

```text
/cancel_pipeline
/deploy staging
/deploy_staging
```

### Confirmation timeout

```text
120 seconds
```

### `/logs` safety limits

```text
Maximum pipeline jobs considered: 20
Maximum trace input: 262,144 bytes
Maximum rendered lines: 40
Maximum rendered characters: 3,000
Sensitive patterns: redacted
```

---

## 21. Related Documentation

- [`../README.md`](../README.md) — project overview and architecture.
- [`installation-configuration.md`](installation-configuration.md) — installation and secure configuration.
- [`threat-model.md`](threat-model.md) — threat model and security boundaries.
- [`backup-recovery.md`](backup-recovery.md) — backup and recovery procedures.

---

## 22. Validated Operational Boundary

At the completion of this guide:

- Telegram RBAC is implemented and tested,
- all documented commands are registered,
- mutating actions use one-time replay-resistant confirmation,
- `/logs` is bounded and redacted,
- retry/cancel targets are selected server-side,
- the fixed security scan does not accept arbitrary profiles,
- AI explanations remain non-authoritative,
- staging deployment is supported,
- Telegram deployment is staging-only; production remains intentionally unprovisioned.

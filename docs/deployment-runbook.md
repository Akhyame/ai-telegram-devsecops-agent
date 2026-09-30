# Deployment Runbook

## 1. Purpose

This runbook documents the validated deployment procedure for the AI DevSecOps Agent Controlled via Telegram.

It covers:

- the authorized staging deployment path,
- the CI/CD validation chain,
- immutable image identity,
- deployment prerequisites,
- post-deployment verification,
- automatic rollback behavior,
- failure handling,
- monitoring handoff,
- the current production boundary.

This runbook does not authorize bypassing GitLab CI/CD, the deterministic Security Gate, RBAC, or Telegram confirmation controls.

---

## 2. Operational Security Boundary

Deployment is controlled by the following security layers:

1. Telegram identity allowlist
2. deterministic RBAC
3. one-time confirmation for deployment actions
4. GitLab API-controlled pipeline creation
5. protected default branch
6. deterministic security scanners
7. deterministic Security Gate
8. environment-specific deployment validation
9. immutable commit-SHA container image
10. runtime health and identity validation

The Policy Engine and Security Gate remain authoritative.

AI explanations cannot authorize, approve, modify, or override deployment decisions.

---

## 3. Validated Environment Status

### Staging

Staging is the validated deployment environment.

The validated Compose project name is:

```text
ai-devsecops-staging
```

The staging API is bound to loopback:

```text
127.0.0.1:18000
```

The container service port remains:

```text
8000/tcp
```

### Production

Production configuration exists in source control, but production is intentionally unprovisioned.

The production Compose project name would be:

```text
ai-devsecops-production
```

The production override defines a loopback API binding:

```text
127.0.0.1:8000
```

However, this project does not claim a validated live production deployment.

Do not provision production only for demonstration or packaging purposes.

---

## 4. Authoritative Deployment Components

The main deployment components are:

```text
deployment/release.sh
deployment/compose.yml
deployment/compose.staging.yml
deployment/compose.production.yml
deployment/config.py
deployment/ci_gate.py
.gitlab-ci.yml
```

Related operational documentation:

```text
docs/telegram-operations-guide.md
docs/security-overview.md
docs/backup-recovery.md
docs/installation-configuration.md
```

---

## 5. Preferred Deployment Entry Point

The preferred operational deployment entry point is Telegram.

For staging, an authorized Admin may use:

```text
/deploy staging
```

or:

```text
/deploy_staging
```

The deployment requires the validated one-time confirmation flow.

The Telegram action does not execute an unrestricted Docker command.

It triggers the controlled GitLab pipeline path.

---

## 6. Deployment RBAC

Deployment is an Admin-only operation.

Viewer and Operator roles must not be able to deploy.

The authorization boundary is deterministic and deny-by-default.

A valid Admin identity is still subject to:

- deployment target allowlisting,
- confirmation,
- GitLab CI rules,
- Security Gate results,
- deployment validation,
- runtime provisioning requirements.

Admin RBAC is necessary but not sufficient to deploy.

---

## 7. Confirmation Requirements

Deployment confirmation is:

- one-time,
- replay-resistant,
- target-bound,
- environment-bound,
- time-limited.

The validated confirmation TTL is:

```text
120 seconds
```

An expired or replayed confirmation must fail.

A confirmation for one environment must not become authorization for another target.

---

## 8. GitLab Pipeline Preconditions

The deployment jobs are constrained by GitLab CI rules.

The validated deployment path requires the deployment pipeline to use:

```text
pipeline_profile = full
```

For staging:

```text
deployment_environment = staging
```

For production:

```text
deployment_environment = production
```

The deployment validation jobs are constrained to the protected default branch and API-triggered deployment workflow.

The current validated default branch is:

```text
main
```

---

## 9. Security Gate Dependency

Deployment is downstream of the deterministic Security Gate.

The validated chain is:

```text
security scanners
→ security_gate
→ security-gate-result.json
→ deployment validation
→ deployment job
```

The deployment validation template consumes:

```text
security-gate-result.json
```

A blocked Security Gate must prevent the deployment path from proceeding.

The deployment script is not an alternate security decision point.

---

## 10. Deployment Validation Jobs

The CI pipeline defines environment-specific validation jobs.

### Staging

```text
validate_staging_deployment
```

Target environment:

```text
staging
```

### Production

```text
validate_production_deployment
```

Target environment:

```text
production
```

The deployment job must not be treated as valid unless its corresponding validation dependency has passed.

---

## 11. Deployment Jobs

The CI configuration includes:

```text
deploy_staging
deploy_staging_monitoring
deploy_production
```

The validated live environment is staging.

`deploy_staging_monitoring` depends on the staging validation and core staging deployment path.

Monitoring deployment remains operationally separate from application rollback semantics.

---

## 12. Release Script Required Inputs

`deployment/release.sh` requires the following deployment inputs:

```text
DEPLOYMENT_ENVIRONMENT
DEPLOYMENT_IMAGE_REPOSITORY
DEPLOYMENT_COMMIT_SHA
DEPLOYMENT_COMPOSE_OVERRIDE
DEPLOYMENT_API_ENV_FILE
DEPLOYMENT_BOT_ENV_FILE
```

It also supports the result path variable:

```text
DEPLOYMENT_RESULT_PATH
```

If no result path is supplied, the default is:

```text
deployment-result.json
```

These variables are internal deployment inputs.

Do not paste their sensitive contents into Telegram, documentation, screenshots, or troubleshooting logs.

---

## 13. Environment Validation

The release script accepts only:

```text
staging
production
```

Any other value fails with an invalid-environment error.

This is an explicit allowlist.

---

## 14. Commit SHA Validation

The target deployment commit must be a full lowercase hexadecimal Git SHA.

The validated format is:

```text
40 hexadecimal characters
```

A short SHA is not accepted by the release script.

This prevents ambiguous image identity.

---

## 15. Image Repository Validation

The deployment image repository is validated before deployment.

The deployment configuration additionally restricts the repository to the GitLab registry boundary.

The expected registry prefix is:

```text
registry.gitlab.com/
```

Repository values containing invalid characters are rejected.

---

## 16. Compose Override Binding

The environment and Compose override are strictly paired.

For staging:

```text
staging:deployment/compose.staging.yml
```

For production:

```text
production:deployment/compose.production.yml
```

Any mismatched environment/override combination is rejected.

This prevents substituting an arbitrary Compose override.

---

## 17. Remote Deployment Target

The release script sets:

```text
DOCKER_HOST=ssh://deployment-target
```

Therefore Docker Compose operations are executed against the configured authorized remote Docker deployment target.

The runbook does not require opening an inbound application port for deployment convenience.

SSH target configuration and credentials must remain outside committed project secrets.

---

## 18. Compose Invocation

The release script wraps Docker Compose using:

```text
docker compose
--project-name <environment project>
--file deployment/compose.yml
--file <environment override>
```

The environment-specific project name is:

```text
ai-devsecops-<environment>
```

The base Compose definition provides the shared hardened runtime configuration.

The environment override supplies environment-specific configuration such as runtime environment files and loopback API publishing.

---

## 19. Runtime Hardening Requirements

The validated runtime security controls include:

- non-root execution,
- read-only root filesystem,
- dropped Linux capabilities,
- `no-new-privileges`,
- health checks,
- restart policy,
- bounded logging,
- loopback API exposure,
- minimized service exposure.

A deployment procedure must not weaken these settings for convenience.

---

## 20. Previous Release Capture

Before replacing an existing release, `release.sh` attempts to capture the current application release.

The previous release is considered valid only when the expected API and Bot runtime state can be established consistently.

The script checks the existing application containers and derives the previous immutable image SHA when possible.

The previous release is used as the rollback candidate if the new deployment fails.

---

## 21. Previous Release Validation

The release script checks the existing API and Bot services before using them as a rollback baseline.

The validation includes:

- service presence,
- expected running state,
- healthy status,
- matching API and Bot image identity,
- image repository boundary,
- valid full commit SHA.

If the previous state exists but is inconsistent or invalid, the deployment fails closed rather than trusting it as a rollback source.

A clean first deployment with no previous release is handled separately from an invalid previous release.

---

## 22. Immutable Deployment Identity

The target release image is identified using the configured image repository and full commit SHA.

Conceptually:

```text
<DEPLOYMENT_IMAGE_REPOSITORY>:<40-character-commit-sha>
```

The API and Bot must run the expected identical immutable image.

Mutable tags such as `latest` are not part of the validated release identity.

---

## 23. Deployment Execution

The release operation uses the validated Docker Compose configuration to start/update the application services.

The release script may pull the target immutable image when required.

After the Compose operation, the script performs release verification before declaring success.

A successful Compose command alone is not sufficient evidence of a successful deployment.

---

## 24. Post-Deployment Service Count Validation

The verification step requires exactly one running API service container and exactly one running Bot service container for the target Compose project.

Unexpected duplicates or missing services cause verification failure.

This prevents silently accepting an ambiguous runtime state.

---

## 25. Post-Deployment Image Validation

The API container image must exactly equal the expected immutable target image.

The Bot container image must exactly equal the same expected immutable target image.

The API and Bot must not be accepted if they are running different image identities.

---

## 26. Container Health Validation

Both application services must report:

```text
healthy
```

The release verification checks Docker health state for:

```text
api
bot
```

A running container that is not healthy is not considered a successful release.

---

## 27. API Readiness Verification

The release script performs an application readiness check inside the API container against:

```text
http://127.0.0.1:8000/health/ready
```

The request uses a bounded timeout.

Failure of the readiness endpoint causes deployment verification failure.

---

## 28. Bot Runtime Verification

The release verification also checks the Bot container through the validated in-container verification path.

The Bot must not merely exist; it must satisfy the runtime verification performed by the release script.

---

## 29. Successful Deployment Result

When the target release passes verification, the script reports:

```text
DEPLOYMENT_RESULT=deployed ROLLBACK=not_required
```

The structured result file includes:

```text
status
environment
target_commit_sha
previous_commit_sha
active_commit_sha
rollback
```

The result is metadata-focused and must not contain secrets.

---

## 30. Configuration Failure

If the composed deployment configuration cannot be validated, the script reports:

```text
DEPLOYMENT_RESULT=configuration_failed
```

The deployment must be treated as failed.

Do not bypass Compose validation by editing the runtime manually.

---

## 31. Invalid Previous Release

If an existing release is detected but cannot be trusted as a valid previous baseline, the script reports:

```text
DEPLOYMENT_RESULT=previous_release_invalid
```

This is a fail-closed state.

The operator must diagnose the current staging runtime before attempting another release.

Do not guess a rollback SHA.

---

## 32. Deployment Verification Failure

If the new target release fails runtime verification, the script reports:

```text
DEPLOYMENT_RESULT=failed ROLLBACK=required
```

At that point the script evaluates whether an automatic rollback candidate is available.

---

## 33. Automatic Rollback

If a valid previous immutable SHA was captured, the release script attempts to redeploy that previous release.

Rollback uses the same controlled deployment and verification mechanism.

Rollback is not a blind container restart.

The previous release must itself pass the normal release verification.

---

## 34. Rollback Success

If the previous release is restored and verified successfully, the script reports:

```text
ROLLBACK_RESULT=succeeded
```

Important operational behavior:

Even when automatic rollback succeeds, the original deployment operation remains a failed deployment and the release script exits non-zero.

Therefore the GitLab deployment job must remain failed.

This is intentional and preserves visibility of the unsuccessful target release.

Do not retry automatically without understanding the original deployment failure.

---

## 35. Rollback Unavailable

If deployment fails and there is no valid previous release SHA, the script reports:

```text
ROLLBACK_RESULT=unavailable
```

This requires controlled recovery rather than guessing a previous version.

Use the recovery procedures documented in:

```text
docs/backup-recovery.md
```

---

## 36. Rollback Failure

If the rollback candidate also fails deployment or verification, the script reports:

```text
ROLLBACK_RESULT=failed
```

This is an incident state.

Do not repeatedly deploy new versions.

Use the known-good recovery workflow and inspect the staging host/runtime condition.

---

## 37. Staging Deployment Procedure

### Step 1 — Confirm repository state

Before requesting deployment, ensure the intended code has been pushed to the protected default branch and CI security checks are expected to run against the correct immutable SHA.

Do not deploy an uncommitted local workspace.

### Step 2 — Request deployment through Telegram

An authorized Admin uses:

```text
/deploy staging
```

or:

```text
/deploy_staging
```

### Step 3 — Review the confirmation

Verify that the confirmation corresponds to the intended:

```text
project
ref
environment
```

Do not approve an unexpected target.

### Step 4 — Confirm within the allowed TTL

Complete the one-time confirmation within:

```text
120 seconds
```

### Step 5 — Observe pipeline creation

Use:

```text
/status
```

to inspect the current pipeline state.

### Step 6 — Allow security validation to complete

The deployment path must remain gated by:

```text
security scanners
security_gate
validate_staging_deployment
deploy_staging
```

Do not bypass a failed or blocked upstream job.

### Step 7 — Verify deployment result

A successful release must satisfy:

```text
DEPLOYMENT_RESULT=deployed
ROLLBACK=not_required
```

and the GitLab deployment job must succeed.

### Step 8 — Verify application status

Use:

```text
/status
```

and controlled runtime evidence.

When host-level validation is required, confirm:

- one API container,
- one Bot container,
- expected immutable image SHA,
- healthy status,
- API readiness,
- staging loopback exposure only.

### Step 9 — Verify monitoring handoff

The staging monitoring job is downstream of validated staging deployment.

Monitoring failure must be investigated independently and must not cause core application rollback.

---

## 38. Telegram Operational Verification

Useful read paths include:

```text
/status
/logs
/explain
/explain security
/explain_security
```

`/logs` is bounded and redacted.

Do not request raw secret-bearing runtime files in Telegram.

AI explanations are diagnostic only and cannot authorize remediation.

---

## 39. Security Scan Before Deployment

The full deployment pipeline includes deterministic security scanning.

The validated scan layers include:

```text
secret_scan
dependency_scan
sast_scan
trivy_filesystem_scan
trivy_image_scan
security_gate
```

Blocking severities are governed by the deterministic policy.

The validated Security Gate blocks:

```text
HIGH
CRITICAL
UNKNOWN
```

---

## 40. Failed Security Gate

If the Security Gate blocks the pipeline:

1. do not attempt a manual Docker deployment;
2. inspect normalized security evidence;
3. use `/explain security` only for explanation;
4. correct the source/configuration issue;
5. create a new commit;
6. rerun the controlled pipeline;
7. require a new successful Security Gate decision.

Never reinterpret AI output as authorization to ignore a Gate block.

---

## 41. Failed Deployment Job

If `deploy_staging` fails:

1. determine the reported deployment state;
2. identify whether rollback was attempted;
3. identify whether rollback succeeded, failed, or was unavailable;
4. inspect bounded job logs;
5. verify current active immutable SHA;
6. verify API and Bot health;
7. do not manually substitute an unvalidated image;
8. follow recovery documentation when necessary.

---

## 42. When Automatic Rollback Succeeds

If:

```text
ROLLBACK_RESULT=succeeded
```

then:

- the attempted target release failed,
- the previous validated release was restored,
- the deployment job remains failed,
- the operator should investigate the failed target before any retry.

Do not classify this as a successful deployment merely because service availability was restored.

---

## 43. When Rollback Is Unavailable

If:

```text
ROLLBACK_RESULT=unavailable
```

then:

- no trusted previous release was available,
- the failed target must not remain assumed healthy,
- select recovery actions from `docs/backup-recovery.md`,
- use a known-good immutable commit SHA,
- validate runtime identity and health after recovery.

---

## 44. When Rollback Fails

If:

```text
ROLLBACK_RESULT=failed
```

treat the event as a staging recovery incident.

Recommended sequence:

1. stop repeated deployment attempts;
2. identify current running containers and immutable image identities;
3. verify the remote Docker target itself is healthy;
4. verify runtime credential/configuration files exist without printing their contents;
5. select a known-good immutable SHA from authoritative Git history;
6. follow the recovery runbook;
7. revalidate application health;
8. revalidate monitoring separately.

---

## 45. Monitoring Deployment Boundary

Application deployment and monitoring deployment are related but distinct.

The CI includes:

```text
deploy_staging_monitoring
```

after validated staging deployment.

Monitoring failure must not automatically roll back a healthy application release.

The monitoring runbook documents Prometheus and Alertmanager provisioning and validation separately.

---

## 46. Production Deployment Procedure

There is currently no validated live production deployment procedure.

Telegram deployment is staging-only and does not expose a production deployment command. The repository still contains production-aware CI and deployment definitions for environment separation:

```text
validate_production_deployment
deploy_production
deployment/compose.production.yml
```

Production remains intentionally unprovisioned.

A future production rollout requires, at minimum:

- separate production credentials,
- validated protected production variables,
- production host provisioning,
- access-control review,
- threat-model review,
- recovery design,
- monitoring retention design,
- production-specific validation evidence,
- explicit authorization to provision production.

Until then, a production deployment request must not be represented as a validated live release capability.

---

## 47. Prohibited Operational Shortcuts

Do not:

- run an arbitrary image tag,
- deploy `latest`,
- bypass the Security Gate,
- edit the target container manually,
- weaken container hardening,
- expose the API publicly for convenience,
- paste runtime credentials into CI logs,
- copy `.env` values into documentation,
- invent a rollback SHA,
- treat AI explanation as authorization,
- provision production for demonstration,
- use monitoring failure as a reason to automatically roll back the core application.

---

## 48. Recovery Reference

For lost containers, monitoring configuration volumes, monitoring data, runtime credential files, or Runner workspace recovery, use:

```text
docs/backup-recovery.md
```

Git and the validated immutable commit SHA remain authoritative for application code and deployment configuration.

---

## 49. Deployment Evidence Checklist

For a validated staging deployment, retain sanitized evidence of:

- target full commit SHA,
- GitLab pipeline ID,
- pipeline source,
- protected default branch,
- successful Security Gate,
- successful staging deployment validation,
- deployment job status,
- deployment result state,
- rollback state,
- active immutable SHA,
- API health,
- Bot health,
- monitoring status where applicable,
- absence of production runtime changes.

Do not retain secret values as deployment evidence.

---

## 50. Final Validation Checklist

A deployment may be considered successfully validated only when all applicable conditions are true:

- authorized Admin initiated the request;
- confirmation was valid and one-time;
- the intended environment was selected;
- the target branch/ref was allowlisted;
- the target image used a full immutable commit SHA;
- all blocking security jobs passed;
- Security Gate returned ALLOW;
- environment deployment validation passed;
- deployment job succeeded;
- API runs the expected image;
- Bot runs the expected image;
- API and Bot images match;
- API and Bot are healthy;
- API readiness passes;
- no unauthorized host exposure was introduced;
- monitoring status is evaluated separately;
- production remained untouched during staging operations.

---

## 51. Related Documentation

- [`telegram-operations-guide.md`](telegram-operations-guide.md) — Telegram commands, RBAC, confirmations, and operational workflows.
- [`security-overview.md`](security-overview.md) — consolidated security architecture and controls.
- [`backup-recovery.md`](backup-recovery.md) — recovery scenarios and backup policy.
- [`installation-configuration.md`](installation-configuration.md) — installation and secure configuration.
- [`../README.md`](../README.md) — project overview and documentation index.

---

## 52. Current Validated Boundary

This runbook documents the validated academic/lab staging deployment architecture.

It does not certify a production environment.

The authoritative operational rule remains:

```text
Security Gate first.
Validated immutable staging deployment second.
Production only after separate provisioning and validation.
```

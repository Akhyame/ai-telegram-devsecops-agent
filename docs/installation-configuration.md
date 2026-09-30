# Installation & Configuration Guide

## 1. Purpose

This guide describes how to prepare, configure, validate, and operate the AI DevSecOps Agent Controlled via Telegram in the validated academic/lab environment.

The documented installation path preserves the project's security model:

- deny-by-default Telegram access;
- separated GitLab read and write credentials;
- deterministic Security Gate enforcement;
- no AI authorization or Security Gate override;
- local secret storage outside Git;
- immutable deployment image references;
- internal-only monitoring services;
- production intentionally unprovisioned.

This document does not provision a production environment.

---

## 2. Validated Environment

The project has been developed and validated with the following baseline:

- Ubuntu Server 24.04 LTS for the runtime host;
- Python `>=3.12,<3.13`;
- Docker Engine;
- Docker Compose;
- Git;
- GitLab repository and CI/CD;
- project-scoped GitLab Runner;
- Telegram Bot API access;
- local Ollama-compatible AI provider.

A Windows workstation can be used for repository development and local Python testing.

---

## 3. Repository Prerequisites

Before installation, ensure that the host has:

1. Git.
2. Python 3.12.
3. Docker Engine.
4. Docker Compose.
5. Network access to GitLab and Telegram.
6. Access to the private GitLab project.
7. A Telegram bot created through BotFather.
8. An Ollama-compatible local AI endpoint if AI explanations are required.
9. A configured GitLab Runner for CI/CD execution.

Do not weaken host, Docker, Runner, or firewall security controls merely to simplify local testing.

---

## 4. Clone the Repository

Clone the private GitLab repository using the authorized SSH identity or another approved GitLab authentication method.

Example:

```bash
git clone <your-private-gitlab-repository>
cd ai-telegram-devsecops-agent
```

The operational project directory should contain at least:

```text
agent/
api/
bot/
deployment/
docs/
gitlab_client/
monitoring/
policy_engine/
sample_app/
scripts/
security/
tests/
.env.example
.gitlab-ci.yml
.gitleaks.toml
Dockerfile
pyproject.toml
security-policy.toml
README.md
```

---

## 5. Python Environment

The project requires:

```text
Python >=3.12,<3.13
```

### Ubuntu

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Verify the environment:

```bash
python --version
pytest
ruff format --check .
ruff check .
```

---

## 6. Local Environment File

The repository contains a safe template:

```text
.env.example
```

Create a local `.env` file from it.

### Ubuntu

```bash
cp .env.example .env
```

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

The real `.env` file is local-only and must remain ignored by Git.

Never:

- commit `.env`;
- paste real tokens into documentation;
- expose tokens in screenshots;
- send credentials through Telegram;
- store private keys or signing secrets in the repository.

Verify that `.env` is not tracked:

```bash
git ls-files .env
```

Expected result: no output.

---

## 7. Environment Variable Reference

The validated `.env.example` currently defines 21 configuration variables.

### 7.1 General Runtime

| Variable | Purpose | Current template default | Sensitive |
| --- | --- | --- | --- |
| `APP_ENV` | Runtime environment identifier used by deployment Compose overlays | `development` | No |
| `LOG_LEVEL` | Application logging level | `INFO` | No |

`APP_ENV` is currently referenced by staging and production Compose overlays rather than directly by Python configuration code.

---

### 7.2 Telegram and RBAC

| Variable | Purpose | Required guidance |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot API credential | Required for bot operation; secret |
| `TELEGRAM_ALLOWED_USER_IDS` | Comma-separated numeric IDs allowed to interact with the bot | Empty means deny everyone |
| `TELEGRAM_OPERATOR_USER_IDS` | Comma-separated Operator IDs | Every Operator must also be allowed |
| `TELEGRAM_ADMIN_USER_IDS` | Comma-separated Administrator IDs | Every Admin must also be allowed |

The authorization model is deny-by-default.

Role intent:

- Viewer: allowed user without a privileged role.
- Operator: operational read/trigger permissions.
- Administrator: privileged actions such as cancellation and deployment.

Do not add an Operator or Administrator ID without also including that ID in `TELEGRAM_ALLOWED_USER_IDS`.

---

### 7.3 GitLab Read Integration

| Variable | Purpose | Current template default |
| --- | --- | --- |
| `GITLAB_API_URL` | GitLab REST API base URL | `https://gitlab.com/api/v4` |
| `GITLAB_PROJECT_ID` | Fixed GitLab project identifier | Empty |
| `GITLAB_DEFAULT_REF` | Allowed/default Git ref | `main` |
| `GITLAB_API_TOKEN` | Project-scoped credential for controlled read operations | Empty / secret |

The application should remain constrained to the configured GitLab project and ref boundaries.

Use the minimum GitLab permissions required for read operations.

---

### 7.4 GitLab Write Integration

| Variable | Purpose | Current template default |
| --- | --- | --- |
| `GITLAB_WRITE_API_TOKEN` | Separate project-scoped credential for controlled write operations | Empty / secret |

Do not reuse the read credential for write actions.

The write credential is used by the controlled GitLab write integration and must have only the permissions required by the implemented pipeline actions.

---

### 7.5 Legacy Template Fields

The following variables are present in `.env.example` but are not referenced by the current Python runtime:

- `GITLAB_URL`
- `GITLAB_TOKEN`

They should not be treated as the primary application configuration.

Current runtime integration uses:

- `GITLAB_API_URL`
- `GITLAB_API_TOKEN`
- `GITLAB_WRITE_API_TOKEN`

Keep legacy fields empty unless a future compatibility requirement explicitly documents otherwise.

---

### 7.6 AI Provider

| Variable | Purpose | Current template default |
| --- | --- | --- |
| `AI_PROVIDER` | AI provider selector | `ollama-local` |
| `OLLAMA_API_URL` | Local Ollama-compatible API endpoint | `http://127.0.0.1:11434/api` |
| `OLLAMA_MODEL` | Local model name | `qwen3.5:4b` |
| `AI_REQUEST_TIMEOUT_SECONDS` | AI request timeout | `60` |
| `AI_MAX_OUTPUT_CHARS` | Maximum bounded AI output size | `1200` |

The AI subsystem is advisory only.

It may explain normalized evidence, but it must not:

- authorize users;
- change RBAC;
- override the Security Gate;
- independently deploy;
- modify GitLab configuration;
- receive unrestricted sensitive logs.

If the AI provider is unavailable, deterministic security controls remain authoritative.

---

### 7.7 Deployment

| Variable | Purpose | Current template default |
| --- | --- | --- |
| `DEPLOYMENT_IMAGE_REPOSITORY` | Approved GitLab Container Registry repository | `registry.gitlab.com/akhyames/ai-telegram-devsecops-agent` |

Deployment must use an immutable commit-SHA image identity generated by the validated CI/CD workflow.

Do not replace the repository with an arbitrary external image source.

The current project supports validated staging deployment.

Production is intentionally unprovisioned.

---

### 7.8 GitLab Webhook Verification

| Variable | Purpose |
| --- | --- |
| `GITLAB_WEBHOOK_SIGNING_TOKEN` | Secret used to authenticate incoming GitLab webhook events |

Generate and store the real value outside Git.

Webhook processing must fail closed when authentication or expected event validation fails.

---

### 7.9 Monitoring Receiver Authentication

| Variable | Purpose |
| --- | --- |
| `ALERTMANAGER_RECEIVER_TOKEN` | Credential used to authenticate Alertmanager events delivered to the application receiver |

The value must be stored only in protected runtime configuration.

Monitoring notifications forwarded to Telegram should contain normalized, minimized information rather than raw sensitive payloads.

---

## 8. Configuration Ownership

The current codebase separates configuration by component.

| Component | Configuration file |
| --- | --- |
| AI agent | `agent/config.py` |
| Telegram RBAC | `bot/config.py` |
| GitLab read integration | `bot/gitlab_config.py` |
| GitLab write integration | `bot/gitlab_write_config.py` |
| Deployment | `deployment/config.py` |
| Security policy loading | `policy_engine/config.py` |
| Sample application logging | `sample_app/config.py` |
| Monitoring receiver | `sample_app/monitoring_alert_config.py` |
| GitLab webhook receiver | `sample_app/webhook_config.py` |

Avoid duplicating configuration logic outside these controlled modules.

---

## 9. Docker Deployment Structure

Deployment configuration is stored under:

```text
deployment/
├── compose.yml
├── compose.staging.yml
├── compose.production.yml
├── config.py
├── ci_gate.py
├── models.py
├── release.sh
└── monitoring.sh
```

The base Compose file uses the configured image repository.

Environment-specific overlays provide staging or production runtime settings.

The staging path is the validated deployment target.

The production overlay exists as a configuration boundary, but the production environment itself is intentionally not provisioned.

---

## 10. Monitoring Configuration

Monitoring files are stored under:

```text
monitoring/
├── alertmanager/
│   └── alertmanager.yml
├── prometheus/
│   ├── alerts.yml
│   └── prometheus.yml
└── grafana/
```

Validated monitoring versions:

- Prometheus `v3.13.2`
- Alertmanager `v0.33.1`

Monitoring services must remain on the internal monitoring network and should not be exposed through unnecessary host ports.

Validated alerts include:

- application unavailable;
- sustained server errors;
- sustained high latency.

Monitoring failure must not trigger application rollback.

---

## 11. Security Gate Configuration

The deterministic security policy is stored in:

```text
security-policy.toml
```

The validated blocking policy includes:

- `HIGH`
- `CRITICAL`
- `UNKNOWN`

Malformed or unknown security evidence fails closed.

The Security Gate, not the AI system, determines whether security evidence allows or blocks progression.

The CI/CD dependency chain is:

```text
Security scanners
      |
      v
security_gate
      |
      v
security-gate-result.json
      |
      v
deployment validation
      |
      v
deployment job
```

A blocking gate result cannot advance to deployment.

---

## 12. GitLab CI/CD Configuration

The main pipeline is defined in:

```text
.gitlab-ci.yml
```

Validated pipeline capabilities include:

- Runner connectivity validation;
- Ruff formatting and quality checks;
- automated Python tests;
- Gitleaks secret scanning;
- pip-audit dependency scanning;
- Semgrep SAST;
- Trivy filesystem scanning;
- container image build;
- Trivy image scanning;
- deterministic Security Gate evaluation.

Credentials used by GitLab CI/CD should be stored as protected GitLab CI/CD variables or other approved secret mechanisms, not in repository files.

Branch, variable, and environment protection must remain enabled according to the validated hardening model.

---

## 13. GitLab Runner

The validated environment uses a dedicated project-scoped GitLab Runner.

Security expectations include:

- project-scoped registration;
- unprivileged Docker executor;
- no unnecessary privileged mode;
- no unnecessary host Docker socket exposure;
- controlled job tags;
- least privilege.

Runner installation and registration are infrastructure operations and should use the GitLab-generated registration/authentication workflow for the target environment.

Do not embed Runner credentials in this repository.

---

## 14. Ollama-Compatible AI Provider

The current AI configuration expects a local Ollama-compatible endpoint.

Validate the AI service independently before starting AI-assisted features.

Example local check:

```bash
curl http://127.0.0.1:11434/api/tags
```

Do not expose the Ollama endpoint publicly merely for convenience.

AI availability is not a prerequisite for deterministic authorization or Security Gate enforcement.

---

## 15. Pre-Run Validation

Before starting services, validate the repository and local configuration.

### Repository status

```bash
git status --short
```

Expected: clean worktree after installation/configuration files are prepared outside Git.

### Python checks

```bash
pytest
ruff format --check .
ruff check .
```

### Environment safety

Confirm:

- `.env` exists locally when required;
- `.env` is ignored by Git;
- no real secrets exist in `.env.example`;
- Telegram allowed-user configuration is explicit;
- GitLab read and write credentials are separate;
- GitLab project/ref boundaries are correct;
- webhook signing is configured;
- Alertmanager receiver authentication is configured;
- production credentials are not configured in the current lab.

---

## 16. Staging Deployment Safety

The staging deployment path must preserve the validated controls:

1. Authorized Administrator requests deployment.
2. The Telegram bot performs RBAC validation.
3. Explicit one-time confirmation is required.
4. GitLab project, ref, and environment boundaries are checked.
5. CI security scanners execute.
6. The deterministic Security Gate evaluates normalized evidence.
7. Deployment validation checks eligibility.
8. The immutable commit-SHA image is deployed.
9. Health validation is performed.
10. Controlled rollback is available if deployment health validation fails.

Do not bypass this chain with a manual image or direct container replacement.

---

## 17. Production Boundary

Production is intentionally unprovisioned in the current environment.

Do not interpret the presence of `compose.production.yml` as evidence of a live production deployment.

Before future production rollout, perform a dedicated production-readiness review covering at least:

- credential ownership and rotation;
- protected deployment approvals;
- persistent ingress and TLS;
- infrastructure resilience;
- backup and restore policy;
- monitoring retention;
- alert ownership;
- secret management;
- runtime capacity;
- incident response;
- rollback ownership;
- audit retention.

---

## 18. Troubleshooting Principles

When installation or configuration fails:

1. Do not print secret values.
2. Check configuration variable presence rather than contents.
3. Check GitLab project/ref identity.
4. Check Telegram RBAC membership.
5. Check Docker and Compose health.
6. Check GitLab Runner status.
7. Check local Ollama availability only for AI-specific failures.
8. Inspect bounded/redacted logs.
9. Preserve deterministic Security Gate decisions.
10. Do not weaken security controls to make a test pass.

---

## 19. Related Documentation

- [`../README.md`](../README.md) — project overview and architecture.
- [`threat-model.md`](threat-model.md) — trust boundaries, threats, mitigations, and residual risk.
- [`backup-recovery.md`](backup-recovery.md) — backup scope and recovery procedures.

Further operational documentation is added progressively during Phase 15.

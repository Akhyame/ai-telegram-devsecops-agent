# Final Threat Model

## Scope

This threat model covers the validated staging architecture of the AI DevSecOps Agent controlled through Telegram.

Production remains intentionally unprovisioned.

## Security Authority

The deterministic security controls are authoritative.

- Telegram identities are authorized deny-by-default.
- RBAC determines permitted commands.
- Mutating actions require replay-resistant confirmation where applicable.
- The Policy Engine decides security-gate ALLOW/BLOCK results.
- High, critical, and unknown severities are blocked.
- AI is read-only and cannot authorize, deploy, remediate, or override the Policy Engine.

## Trust Boundaries

### TB-1 ? Telegram User to Bot

Threats:
- unauthorized users;
- privilege escalation;
- command flooding;
- replay of privileged confirmations.

Controls:
- explicit user allowlist;
- deterministic RBAC;
- per-user rate limiting;
- bounded one-time confirmations with TTL and replay resistance.

### TB-2 ? Bot to GitLab

Threats:
- misuse of privileged API operations;
- credential misuse;
- unauthorized pipeline execution.

Controls:
- separated read/write credentials;
- protected variables;
- protected main branch;
- protected staging environment;
- disabled arbitrary CI variable overrides;
- controlled confirmation for privileged actions.

### TB-3 ? AI Boundary

Threats:
- prompt injection;
- misleading explanations;
- attempted AI authorization.

Controls:
- normalized bounded input;
- fixed read-only AI role;
- validated output;
- AI cannot change RBAC, confirmation, deployment, or Policy Engine decisions.

### TB-4 ? Policy Engine

Threats:
- high-risk findings bypassing the gate;
- malformed or weakened policy configuration.

Controls:
- deterministic ALLOW/BLOCK evaluation;
- high and critical severities blocked;
- unknown severity blocked;
- strict policy configuration validation.

### TB-5 ? GitLab Webhook

Threats:
- forged requests;
- replay;
- oversized requests;
- request flooding.

Controls:
- HMAC authentication;
- timestamp freshness;
- replay guard;
- body-size bounds;
- authenticated rate limiting;
- normalized processing.

### TB-6 ? CI/CD and Docker Staging

Threats:
- deployment identity substitution;
- container privilege escalation;
- host exposure.

Controls:
- immutable commit/image identity;
- pinned dependencies and images;
- non-root containers;
- read-only root filesystems;
- dropped capabilities;
- no-new-privileges;
- no Docker socket exposure;
- loopback-only API exposure;
- internal monitoring network.

### TB-7 ? Monitoring

Threats:
- forged monitoring notifications;
- receiver flooding;
- monitoring failure affecting deployment.

Controls:
- dedicated Bearer authentication;
- authenticated rate limiting;
- bounded alert normalization;
- monitoring failure cannot trigger core application rollback.

### TB-8 ? Credentials and Recovery

Threats:
- credential disclosure;
- unsafe backups;
- credential reuse after compromise.

Controls:
- credential separation;
- protected staging variables;
- .env excluded from Git;
- plaintext secret backups prohibited;
- secure re-provisioning and rotation;
- production credentials absent.

## Key Residual Risks

Accepted staging residual risks include:

- compromise of an authorized Telegram account;
- compromise of a GitLab Maintainer account;
- compromise of the staging Docker or Runner host;
- scanner false negatives;
- inaccurate AI explanations;
- provider-level volumetric denial of service;
- loss of historical monitoring metrics;
- external GitLab, Telegram, registry, or AI outages.

These residual risks do not grant AI authorization authority.

## Security Invariants

1. The Policy Engine is deterministic and authoritative.
2. AI cannot authorize, override, deploy, or remediate independently.
3. Invalid Telegram identities fail closed.
4. RBAC remains deterministic.
5. Privileged confirmations remain one-time and replay-resistant.
6. High, critical, and unknown findings cannot silently pass the configured gate.
7. Webhook authentication occurs before trusted processing.
8. Monitoring authentication occurs before trusted processing.
9. Secrets are never committed to Git or stored in plaintext project backups.
10. Monitoring failure never initiates core application rollback.
11. Production remains unprovisioned until separately designed and validated.
12. Recovery must preserve these security boundaries.

## Production Limitations

This document is not production certification.

Before production use, the threat model must be revisited for:

- production credential lifecycle;
- approval workflows;
- centralized durable audit logging;
- encrypted backups;
- monitoring retention;
- high availability;
- host and Runner hardening;
- network-level ingress protection;
- disaster recovery objectives;
- external secret management;
- incident response.

# Security Policy

## Scope

This repository implements the AI Security Gateway. Security-relevant
components: authentication/authorization, security detectors, policy engine,
document ingestion, LLM integration, observability/audit.

## Reporting

This is a portfolio/MSc project. For issues, open a GitHub issue with the
`security` label; do not include real secrets or live endpoints in reports.

## Security decisions in this codebase

- Fail-closed for: input security, context security uncertainty, policy
  loading, output security. Fail-open only for observability and RAG
  availability — full matrix in docs/security-model.md
- All detector decisions are explainable (evidence + reason + version)
- Policies are versioned; invalid policies can never activate
- Passwords: scrypt; JWTs: HS256 with expiry, never logged
- All secrets/PII are redacted before logging or storage
- Uploads: content sniffing, extension allow-list, filename sanitization,
  size caps, no execution, path-traversal-safe storage names
- SQL: ORM-parameterized only; no string-built SQL anywhere

## Known limitations (honesty required)

- Deterministic detectors provide probabilistic risk reduction, not
  prevention. Measured results: docs/evaluation-report.md. Do not treat the
  gateway as a substitute for model-level safety or platform hardening.
- The default development credentials in `.env.example`/compose are for local
  development only and must be changed before any shared deployment.
- Production deployments need TLS, secret management (e.g. vault), and
  centralized logging — out of scope for the laptop target, checklist in
  docs/security-model.md.

## Dependency policy

Dependencies are pinned in backend/requirements.txt and reviewed on updates.
The Docker image runs as a non-root user.

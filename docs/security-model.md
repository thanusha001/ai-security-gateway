# Security Model

## Detection result contract

Every detector returns a `DetectionResult` (Pydantic): `detector`,
`detector_version`, `threat_type`, `severity`, `confidence`, `risk_score`,
`action`, `reason`, `evidence[]`, `latency_ms`. Actions:

| Action | Meaning |
|---|---|
| ALLOW | no threat; proceed |
| REDACT | sanitize text (secrets/PII → placeholders), proceed with redacted copy |
| SANITIZE | soft handling for uncertain signals (score 0.30–0.59) |
| ESCALATE | flag for human review (policy-mapped) |
| BLOCK | refuse to proceed; evidence recorded |

Classification bands: `risk < 0.30` SAFE · `0.30–0.59` SUSPICIOUS ·
`≥ 0.60` MALICIOUS (per policy thresholds) · UNKNOWN → fail-closed for
context security.

## Risk aggregation

NOT a naive average (a single 0.9 signal among ten 0.0 detectors must not
become 0.09). Documented formula:

```
risk = 0.6 * max(detector_scores) + 0.4 * weighted_average(detector_scores)
```

- `max` preserves a single strong signal
- `weighted_average` lets multiple medium signals accumulate
- detector weights are configurable (`RiskConfig.weights`), e.g. PII 0.6
  (privacy issue, not attack) vs prompt_injection 1.0 (attack)

Bands (initial, REQUIRE empirical tuning): LOW < 0.30 ≤ MEDIUM < 0.60 ≤
HIGH < 0.80 ≤ CRITICAL.

## Policy engine

- Policies are rows in `security_policies` with integer `version`; updates
  create a new immutable version; activation validates the configuration
  (Pydantic, `extra=forbid`) — **invalid policies can never become active**
- Every request records `policy_id` + `policy_version`
- Per-rule trace (threshold, score, triggered) is persisted in the event store
  and rendered in the request-detail UI
- If no policy exists: built-in defaults keep the gateway functional
- If the active policy fails validation at load: gateway fails closed (503)

## Fail-open vs fail-closed matrix

| Component | On failure | Rationale |
|---|---|---|
| Input security scan crashes | **fail-closed** (request blocked, 500) | cannot assert safety |
| Context security uncertain (UNKNOWN status) | **fail-closed** (chunk excluded) | policy default |
| Policy store unavailable | **fail-closed** (503) | no enforcement without policy |
| Active policy invalid | **fail-closed** (503) | same |
| Retrieval/embedding failure | **fail-open for availability** (RAG skipped, request continues, degradation recorded) | RAG is an enhancement, not a security control |
| Event persistence | **fail-open** (logged, request continues) | observability must not break the request |
| LLM unavailable/timeout | controlled error (503/504) | never crash the API |
| Output security scan | **fail-closed** (response blocked) | never return unscanned model output |

## Authentication / authorization

- JWT (HS256, exp), scrypt password hashing, roles ADMIN/USER/AUDITOR
- Role matrix: ADMIN manage all; USER submit requests + view own; AUDITOR
  read-only security/audit views
- Tokens never logged; passwords never stored or logged in plaintext
- 401 vs 403 distinguished; inactive users rejected at token validation

## Privacy & data retention

- `STORE_RAW_PROMPTS` / `STORE_RAW_OUTPUTS` (default true for local
  development — **documented privacy trade-off**); when false, text is stored
  as `[REDACTED:storage disabled]`
- Input text is redacted (secrets/PII) before storage when detectors fire and
  before it is embedded or sent to the LLM
- Retention: `AUDIT_RETENTION_DAYS` (90), `SECURITY_EVENT_RETENTION_DAYS`
  (180); cleanup via `scripts/maintenance.py [--dry-run] [--purge-prompts]`
- Logs are JSON with redaction of secrets/credentials; evidence stores
  truncated matches, never full secrets

## Secrets handling in the gateway itself

- No credentials in code; `.env` is git-ignored, `.env.example` documents keys
- Bootstrap admin password from env; change before real use
- Database credentials are compose-level dev defaults; rotate for production

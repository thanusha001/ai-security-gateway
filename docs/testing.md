# Testing

## Backend

```bash
cd backend
.venv/Scripts/python -m pytest -q          # Windows
.venv/bin/python -m pytest -q              # macOS/Linux
```

- `tests/test_security_smoke.py` — 30 unit tests: every detector (attack +
  benign), output security, risk engine (signal preservation, thresholds),
  policy engine (BLOCK/REDACT/ALLOW), chunking (overlap, invalid params),
  log redaction, full input pipeline aggregation.
- Integration tests (DB/Ollama required) are separated and skip cleanly when
  services are absent so unit runs stay hermetic.

Key security cases covered (spec §46): normal→ALLOW, injection→BLOCK,
secret→REDACT, benign policy text not flagged, JWT redaction, PII Luhn
filtering, policy threshold behavior, multi-threat aggregation.

## Frontend

```bash
cd frontend
npm test        # vitest: StatusBadge semantics, state views (error shows request_id)
npx tsc -b      # strict typecheck
npm run build   # production build
```

## Detector evaluation (separate from tests)

```bash
python scripts/evaluate_detectors.py
```

Produces `docs/evaluation-report.md` with per-detector TP/TN/FP/FN, precision,
recall, F1, FPR, FNR, latency percentiles — see [evaluation-report.md](evaluation-report.md).

## Manual verification checklist (acceptance criteria)

1. `docker compose up -d postgres` healthy
2. `alembic upgrade head` + `python -m app.bootstrap` succeed
3. `/health` reports components
4. Login → submit normal prompt → ALLOW with LLM response (Ollama up)
5. Injection prompt → BLOCK with evidence in UI trace
6. Secret prompt → REDACT, stored text has placeholders
7. Upload safe PDF → TRUSTED; poisoned document → chunk BLOCKED and excluded
   from retrieval (see `retrieval_events.exclusion_reason`)
8. LLM down → controlled LLM_UNAVAILABLE with request_id
9. Invalid JWT → 401; AUDITOR POST policy → 403; 61st rapid request → 429
10. Metrics/audit/trace endpoints return real recorded data

# Database

PostgreSQL 16 + pgvector. SQLAlchemy 2 async ORM, Alembic migrations.

## Tables (14)

| Table | Purpose | Key columns |
|---|---|---|
| `users` | accounts | email (unique), password_hash (scrypt), role, is_active |
| `security_policies` | versioned policies | name+version unique, configuration_json, is_active |
| `requests` | one row per gateway request | request_id (unique), user_id FK, risk_score, risk_level, final_decision, policy_id/version, total_latency_ms, error_code |
| `security_events` | stage/detector event log | request_id, stage, event_type, detector, detector_version, evidence_json, latency_ms |
| `threat_detections` | normalized threats | request_id, threat_type, detector, confidence, risk_score |
| `documents` | ingested docs | document_id (unique), sha256_hash (unique), status, trust_score, risk_score, chunk_count |
| `document_chunks` | chunks + embeddings | document_id FK CASCADE, chunk_index, embedding vector(384), security_status, risk_score, page_number |
| `document_security_scans` | scan records | document_id FK, scan_type, threats_json, duration_ms |
| `retrieval_events` | per-chunk retrieval audit | request_id, document_id, chunk_id, similarity, included, exclusion_reason |
| `llm_requests` | LLM call observability | request_id, provider, model, tokens (exact/estimated), ttft, latency, tokens_per_second, error_code |
| `llm_responses` | model outputs | llm_request_id FK CASCADE, response_text, security_status, redacted |
| `audit_logs` | human actions | user_id, action, resource_type/id, details_json, ip_address |
| `rate_limit_events` | limiter decisions | user_id, endpoint, client_identifier, allowed |

## Indexes

- unique: `users.email`, `requests.request_id`, `documents.document_id`,
  `documents.sha256_hash`, `security_policies (name, version)`
- btree: request_id lookups, `security_events (request_id, stage)` composite,
  `created_at` on event/audit tables, chunk `(document_id, chunk_index)`,
  `document_chunks.security_status`
- vector: `document_chunks USING hnsw (embedding vector_cosine_ops)` for
  cosine similarity ANN search

## Vector search

`app/rag/vector_search.py` — cosine similarity via pgvector
`1 - cosine_distance`, hard filter `security_status != 'BLOCKED'` (never
retrievable regardless of policy), SUSPICIOUS excluded unless the active
policy sets `allow_suspicious_chunks`, document-UID filtering, min-similarity
cutoff, over-fetch + top_k trim.

## Transaction safety (spec §24)

- Document ingestion: row starts PENDING → SCANNING → PROCESSING →
  TRUSTED/SUSPICIOUS/BLOCKED in one transaction with chunks. Any failure
  rolls back and persists a FAILED row (re-upload allowed).
- Requests: created PROCESSING; terminal states COMPLETED / BLOCKED / REDACT /
  FAILED with `error_code`; every stage failure is persisted before responding.
- Retries: unique constraints (hash, request_id) make retries idempotent.

## Migrations

```bash
cd backend
alembic upgrade head
alembic revision --autogenerate -m "..."
alembic downgrade -1
```

Initial migration `0001_initial` creates the `vector` extension, all tables
via ORM metadata, and the HNSW index.

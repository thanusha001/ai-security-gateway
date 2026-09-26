# API Reference

Base URL: `http://localhost:8000`. Interactive docs: `/docs` (Swagger UI),
`/openapi.json`. All errors use the standard envelope:

```json
{"error": {"code": "LLM_UNAVAILABLE", "message": "...", "request_id": "...", "details": {}}}
```

## Health (no auth)

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | component status: api, database, vector_db, ollama, embedding_model; overall healthy/degraded/unhealthy |

## Auth

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/auth/register` | — | creates USER; 409 on duplicate email |
| POST | `/api/v1/auth/login` | — | returns JWT + user; audited |
| GET | `/api/v1/auth/me` | any | current user |

## Chat

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/chat` | USER, ADMIN | runs the full pipeline; 429 on rate limit; LLM_UNAVAILABLE 503 / LLM_TIMEOUT 504; returns request_id, decision, risk, policy version, latency |

Request: `{"message": "...", "session_id": "...?", "top_k": 5?}`

## Documents

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/documents/upload` | USER, ADMIN | multipart `file`; scans + embeds; 400/409/413 error codes; DUPLICATE_DOCUMENT with REUSE default |
| GET | `/api/v1/documents` | all roles | last 200 documents with status/scores |
| GET | `/api/v1/documents/{id}/chunks` | all roles | chunk security detail (404 unknown id) |

## Policies

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/policies` | ADMIN, AUDITOR | all versions |
| POST | `/api/v1/policies` | ADMIN | validate + create (inactive) |
| PUT | `/api/v1/policies/{id}` | ADMIN | edit = new immutable version |
| POST | `/api/v1/policies/{id}/activate` | ADMIN | validates before activation |
| POST | `/api/v1/policies/{id}/deactivate` | ADMIN | — |

## Observability

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/api/v1/requests` | all (USER = own) | summaries |
| GET | `/api/v1/requests/{request_id}` | all (USER = own) | full trace: events, retrievals, llm, threats |
| GET | `/api/v1/events?severity=&detector=` | ADMIN, AUDITOR | security event log |
| GET | `/api/v1/threats` | ADMIN, AUDITOR | threat detections |
| GET | `/api/v1/metrics` | all | real aggregates (counts, avg/P95 latency, tokens, detector counts) |
| GET | `/api/v1/llm/usage` | ADMIN, AUDITOR | per-model usage + token_count_source |
| GET | `/api/v1/audit?action=&user_id=` | ADMIN, AUDITOR | audit log |
| GET | `/api/v1/stream` | any | SSE pipeline events (keepalive every 15 s) |

## Error codes

VALIDATION_ERROR · AUTHENTICATION_FAILED · AUTHORIZATION_FAILED ·
RATE_LIMITED · DOCUMENT_TOO_LARGE · UNSUPPORTED_FILE · INVALID_FILE ·
DUPLICATE_DOCUMENT · DOCUMENT_PROCESSING_FAILED · EMBEDDING_FAILED ·
VECTOR_DB_UNAVAILABLE · LLM_UNAVAILABLE · LLM_TIMEOUT · LLM_ERROR ·
SECURITY_BLOCKED · POLICY_VIOLATION · OUTPUT_BLOCKED · NOT_FOUND ·
INTERNAL_ERROR

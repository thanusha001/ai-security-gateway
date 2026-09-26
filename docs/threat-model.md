# Threat Model

Scope: the gateway itself, the LLM/RAG pipeline it protects, and the data it
processes. Trust boundary: client ↔ gateway ↔ (Ollama, PostgreSQL, embedding
model).

## Threats and controls

| # | Threat | Control | Where |
|---|---|---|---|
| 1 | Direct prompt injection | `prompt_injection` detector (rules + optional LLM classifier), policy BLOCK | input security |
| 2 | Indirect prompt injection | `rag_poisoning` detector on documents AND retrieved chunks | doc scan + context security |
| 3 | Jailbreak attempts | `jailbreak` detector with context suppression | input security |
| 4 | System prompt extraction | extraction phrase rules (injection detector), output leakage scan | input + output security |
| 5 | Instruction override | directive-phrase rules, multi-signal scoring | input security |
| 6 | Sensitive data leakage | `secret_detection` on input AND output with redaction | input + output security |
| 7 | PII leakage | `pii_detection` with redaction placeholders | input + output security |
| 8 | API key/secret leakage | AKIA/GitHub/Google/Stripe/Slack/JWT/bearer/private-key patterns | secret detector |
| 9 | Credential leakage | credential-assignment + connection-string patterns | secret detector |
| 10 | RAG document poisoning | document scan → chunk TRUSTED/SUSPICIOUS/BLOCKED; trust/risk scores | ingestion |
| 11 | Malicious retrieved context | context security re-scan; SUSPICIOUS excluded by default; BLOCKED hard-excluded | context security |
| 12 | Unauthorized document access | role-gated upload/read; USER sees own requests only | API authz |
| 13 | Prompt manipulation via documents | poisoning detector + untrusted-context prompt framing | ingestion + prompt build |
| 14 | Malicious model output | output security scan; REDACT/BLOCK before response | output security |
| 15 | Unsafe URLs | `UNSAFE_URL_PATTERN` (private/link-local ranges) | patterns (detection) |
| 16 | Tool/agent abuse architecture | gateway has no tool execution; LLM receives data-only context | architecture |
| 17 | Excessive permissions | three roles, least privilege, dependency-injected checks | auth |
| 18 | Request abuse / flooding | sliding-window rate limits per endpoint; 429 + recorded events | rate limiter |
| 19 | Oversized payloads | content-length middleware (413) + upload size check | middleware |
| 20 | Malformed requests | Pydantic validation → 422 envelope; strict typing everywhere | API layer |
| 21 | Malicious file uploads | content sniffing (magic bytes), extension allow-list, filename sanitization, no execution | ingestion |
| 22 | Unsupported files | allow-list (pdf/docx/txt/md) with clear error | ingestion |
| 23 | Duplicate documents | SHA-256 dedup with REUSE/REJECT/REPROCESS modes | ingestion |
| 24 | Database failures | pool_pre_ping, timeouts, controlled 503, FAILED status persisted | session + services |
| 25 | LLM timeout/failure | httpx timeouts → LLM_TIMEOUT/LLM_UNAVAILABLE controlled errors | Ollama provider |
| 26 | Embedding failure | timeout + controlled EMBEDDING_FAILED; RAG degrades, request continues | embeddings |
| 27 | Vector DB failure | pgvector errors surface as controlled errors; retrieval marked failed | vector search |
| 28 | Partial pipeline failure | per-stage events + STAGE_FAILED; request row keeps failure state | chat service |
| 29 | Logging failure | logging is side-effect only; never blocks request path | logging |
| 30 | Policy configuration errors | Pydantic validation; invalid policy can never activate; fail-closed fallback | policy service |

## Classification principle

Detectors return one of SAFE / SUSPICIOUS / MALICIOUS (via risk score bands)
or UNKNOWN. Unusual input is not automatically malicious: benign policy
language, security documentation, and defensive phrasing are explicitly
suppressed (see evaluation FP cases). UNKNOWN on context security is
fail-closed by policy default.

## Out of scope (documented limitations)

- Host hardening (disk encryption, EDR), production TLS termination
- Multi-tenant isolation beyond role checks
- Novel zero-day injection grammar (mitigated but not eliminated; see
  evaluation report limitations)

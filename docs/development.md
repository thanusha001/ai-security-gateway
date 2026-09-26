# Development Guide

## Local setup (backend)

```bash
cd backend
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Windows
.venv/Scripts/pip install sentence-transformers==3.3.1   # optional/heavy (torch)
alembic upgrade head
python -m app.bootstrap
.venv/Scripts/uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev       # http://localhost:5173, /api proxied to :8000
```

## Code conventions

- Type hints everywhere; Pydantic models for all API boundaries
- Services own business logic; routes stay thin
- Detectors implement `SecurityDetector`; bump `version` on behavior changes
- All configuration through `app.core.config.settings` (env-driven)
- Errors: raise `GatewayError(code, message, status)`; handlers build the envelope
- Logging: `get_logger(__name__)`, kwargs style, redaction automatic
- No SQL string concatenation — ORM/parameterized only
- No secrets in code or logs (redaction filters + `.gitignore`)

## Adding a detector

1. Create `app/security/detectors/my_detector.py` implementing the interface
2. Add patterns to `app/security/patterns.py` (shared with log redaction)
3. Register in `detectors/__init__.py`; add to pipelines as appropriate
4. Add labeled cases to `data/security_tests/detector_dataset.json`
5. Re-run evaluation; add unit tests

## Adding an LLM provider

1. Implement `LLMProvider` (generate, stream, health_check, count_tokens, model_info)
2. Register in `provider_factory.py`
3. Set `LLM_PROVIDER=<name>` + credentials via env

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `embedding_model: unavailable` in /health | sentence-transformers not installed — `pip install sentence-transformers` (torch included). RAG retrieval disabled until then; everything else works. |
| `ollama: unavailable` | `ollama serve` not running or wrong `LLM_BASE_URL` |
| 503 LLM_UNAVAILABLE | Ollama down or model not pulled (`ollama pull qwen3:4b`) |
| Login 401 after bootstrap | ADMIN_EMAIL/ADMIN_PASSWORD env not set when bootstrap ran |
| pgvector extension error | use `pgvector/pgvector:pg16` image; migration creates extension |
| SSE not updating behind nginx | keep `proxy_buffering off` (see frontend/nginx.conf) |

## Performance notes (measured locally, laptop CPU)

- Input security (5 detectors): avg ~0.4 ms, P99 < 1 ms per message
- Embedding (MiniLM on CPU): ~10–30 ms per query
- LLM latency is dominant and model-dependent; see LLM Usage page for live
  tokens/sec from your hardware

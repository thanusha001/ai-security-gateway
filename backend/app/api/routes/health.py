"""Health endpoints (spec §50)."""
from __future__ import annotations

import httpx
from fastapi import APIRouter
from sqlalchemy import text

from app.core.config import settings
from app.database.session import check_database, engine
from app.rag.embeddings import health_check as embedding_health

router = APIRouter(tags=["health"])


async def _ollama_health() -> bool:
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(f"{settings.llm_base_url}/api/tags")
            return resp.status_code == 200
    except (httpx.HTTPError, ValueError):
        return False


# Served under /api/v1 (what the dashboard and nginx proxy call) and kept on
# the bare path for ops curl checks (README / monitoring probes).
@router.get("/api/v1/health")
@router.get("/health")
async def health() -> dict:
    db_ok = await check_database()
    ollama_ok = await _ollama_health()
    embedding_ok = await embedding_health()

    components = {
        "api": "healthy",
        "database": "healthy" if db_ok else "unavailable",
        "vector_db": "healthy" if db_ok else "unavailable",  # pgvector lives in postgres
        "ollama": "healthy" if ollama_ok else "unavailable",
        "embedding_model": "healthy" if embedding_ok else "unavailable",
    }
    unhealthy = [k for k, v in components.items() if v != "healthy"]
    if not unhealthy:
        overall = "healthy"
    elif unhealthy in (["ollama"], ["ollama", "embedding_model"]):
        overall = "degraded"  # LLM down: gateway still serves security decisions
    else:
        overall = "unhealthy"
    return {"status": overall, "components": components}

"""Embedding service.

sentence-transformers (and its torch dependency) is loaded lazily: the API
can start and serve health checks even before the model is available. All
calls run in a worker thread with a timeout so a hung model can't stall the
event loop.
"""
from __future__ import annotations

import asyncio

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("embeddings")

_model = None
_load_lock = asyncio.Lock()


class EmbeddingError(Exception):
    def __init__(self, message: str, code: str = "EMBEDDING_FAILED") -> None:
        super().__init__(message)
        self.code = code  # EMBEDDING_FAILED | EMBEDDING_UNAVAILABLE


def _load_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        log.info("loading_embedding_model", model=settings.embedding_model)
        _model = SentenceTransformer(settings.embedding_model)
    return _model


async def embed_texts(texts: list[str]) -> list[list[float]]:
    """Embed texts, returning lists of floats (pgvector-compatible)."""
    if not texts:
        return []
    try:
        async with asyncio.timeout(settings.embedding_timeout_seconds):
            return await asyncio.to_thread(_embed_sync, texts)
    except TimeoutError as exc:
        raise EmbeddingError("Embedding timed out", code="EMBEDDING_FAILED") from exc
    except Exception as exc:
        raise EmbeddingError(f"Embedding failed: {exc}") from exc


def _embed_sync(texts: list[str]) -> list[list[float]]:
    model = _load_model()
    vectors = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return [v.tolist() for v in vectors]


async def embed_query(text: str) -> list[float]:
    result = await embed_texts([text])
    return result[0]


async def health_check() -> bool:
    """True if the embedding model loads and can encode a short string."""
    try:
        async with asyncio.timeout(settings.embedding_timeout_seconds):
            await asyncio.to_thread(_embed_sync, ["health check"])
        return True
    except Exception:
        return False

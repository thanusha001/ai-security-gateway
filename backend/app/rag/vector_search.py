"""Vector search over pgvector with security filtering.

BLOCKED chunks are never retrievable (hard filter, not policy-dependent).
SUSPICIOUS chunks are excluded by default; inclusion requires the active
policy's allow_suspicious_chunks flag (spec §15).
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select, text as sql_text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.database.models import Document, DocumentChunk


@dataclass
class RetrievedChunk:
    chunk_id: int
    document_id: int
    document_uid: str
    filename: str
    chunk_index: int
    text: str
    similarity: float
    security_status: str
    page_number: int | None
    section: str | None


async def search_similar_chunks(
    db: AsyncSession,
    query_embedding: list[float],
    top_k: int | None = None,
    min_similarity: float | None = None,
    allow_suspicious: bool = False,
    document_uids: list[str] | None = None,
) -> list[RetrievedChunk]:
    top_k = top_k or settings.top_k
    min_similarity = settings.min_similarity if min_similarity is None else min_similarity

    # cosine distance in pgvector: 1 - cosine_similarity
    stmt = (
        select(
            DocumentChunk.id,
            DocumentChunk.document_id,
            Document.document_id.label("document_uid"),
            Document.filename,
            DocumentChunk.chunk_index,
            DocumentChunk.text,
            DocumentChunk.page_number,
            DocumentChunk.section,
            DocumentChunk.security_status,
            (1 - DocumentChunk.embedding.cosine_distance(query_embedding)).label("similarity"),
        )
        .join(Document, DocumentChunk.document_id == Document.id)
        .where(
            DocumentChunk.embedding.is_not(None),
            DocumentChunk.security_status != "BLOCKED",  # hard security filter
            Document.status.notin_(["BLOCKED", "FAILED"]),
        )
        .order_by(text("similarity DESC"))
        .limit(top_k * 3)  # over-fetch to allow post-filters
    )
    if not allow_suspicious:
        stmt = stmt.where(DocumentChunk.security_status != "SUSPICIOUS")
    if document_uids:
        stmt = stmt.where(Document.document_id.in_(document_uids))

    result = await db.execute(stmt)
    rows = result.all()
    return [
        RetrievedChunk(
            chunk_id=r.id,
            document_id=r.document_id,
            document_uid=r.document_uid,
            filename=r.filename,
            chunk_index=r.chunk_index,
            text=r.text,
            similarity=round(float(r.similarity), 4),
            security_status=r.security_status,
            page_number=r.page_number,
            section=r.section,
        )
        for r in rows
        if float(r.similarity) >= min_similarity
    ][:top_k]

"""Document API schemas."""
from __future__ import annotations

from pydantic import BaseModel, Field


class DocumentOut(BaseModel):
    document_id: str
    filename: str
    sha256_hash: str
    file_type: str
    file_size: int
    source: str | None
    status: str
    trust_score: float
    risk_score: float
    chunk_count: int
    created_at: str | None = None
    updated_at: str | None = None


class DocumentUploadResponse(BaseModel):
    document_id: str | None
    status: str  # TRUSTED | SUSPICIOUS | BLOCKED | FAILED | DUPLICATE_DOCUMENT
    detail: str
    duplicate: bool = False
    trust_score: float | None = None
    risk_score: float | None = None
    chunk_count: int | None = None
    threats: list[dict] = Field(default_factory=list)


class ChunkOut(BaseModel):
    chunk_id: int
    chunk_index: int
    page_number: int | None
    security_status: str
    risk_score: float
    reason: str | None = None
    text_preview: str | None = None

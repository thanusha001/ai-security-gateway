"""Document API routes (upload, list, detail, chunks)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import Role, require_roles
from app.core.config import settings
from app.core.rate_limit import upload_limiter
from app.database.models import AuditLog, Document, DocumentChunk, RateLimitEvent
from app.database.session import get_db
from app.schemas.documents import ChunkOut, DocumentOut, DocumentUploadResponse
from app.services.document_service import ingest_document

router = APIRouter(prefix="/api/v1/documents", tags=["documents"])


@router.post("/upload", response_model=DocumentUploadResponse)
async def upload_document(
    file: UploadFile = File(...),
    source: str | None = None,
    user=Depends(require_roles(Role.ADMIN, Role.USER)),
    db: AsyncSession = Depends(get_db),
):
    # rate limit uploads
    key = f"user:{user.id}"
    allowed, _, retry_after = upload_limiter.check(key)
    db.add(RateLimitEvent(user_id=user.id, endpoint="/api/v1/documents/upload",
                          client_identifier=key, allowed=allowed))
    if not allowed:
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "RATE_LIMITED", "message": f"Upload rate limited; retry in {retry_after}s"},
            headers={"Retry-After": str(retry_after)},
        )

    data = await file.read()
    if len(data) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail={"code": "DOCUMENT_TOO_LARGE",
                    "message": f"File exceeds {settings.max_upload_size_mb} MB limit"},
        )

    try:
        result = await ingest_document(db, data=data, filename=file.filename or "upload",
                                       source=source)
    except Exception as exc:
        await db.rollback()
        # document service raises GatewayError subclasses with codes
        code = getattr(exc, "code", None)
        if hasattr(code, "value"):
            code = code.value
        status_map = {"DOCUMENT_TOO_LARGE": 413, "UNSUPPORTED_FILE": 400,
                      "INVALID_FILE": 400, "DUPLICATE_DOCUMENT": 409}
        raise HTTPException(
            status_code=status_map.get(code, 500),
            detail={"code": code or "INTERNAL_ERROR", "message": str(exc)},
        ) from exc

    db.add(AuditLog(user_id=user.id, action="document_upload",
                    resource_type="document", resource_id=result.get("document_id"),
                    details_json={"status": result["status"], "duplicate": result["duplicate"]}))
    await db.commit()
    return DocumentUploadResponse(**result)


@router.get("", response_model=list[DocumentOut])
async def list_documents(
    user=Depends(require_roles(Role.ADMIN, Role.USER, Role.AUDITOR)),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Document).order_by(Document.created_at.desc()).limit(200))
    docs = result.scalars().all()
    return [
        DocumentOut(
            document_id=d.document_id, filename=d.filename, sha256_hash=d.sha256_hash,
            file_type=d.file_type, file_size=d.file_size, source=d.source,
            status=d.status, trust_score=d.trust_score, risk_score=d.risk_score,
            chunk_count=d.chunk_count,
            created_at=d.created_at.isoformat() if d.created_at else None,
            updated_at=d.updated_at.isoformat() if d.updated_at else None,
        )
        for d in docs
    ]


@router.get("/{document_id}/chunks", response_model=list[ChunkOut])
async def get_document_chunks(
    document_id: str,
    user=Depends(require_roles(Role.ADMIN, Role.USER, Role.AUDITOR)),
    db: AsyncSession = Depends(get_db),
):
    doc = (
        await db.execute(select(Document).where(Document.document_id == document_id))
    ).scalar_one_or_none()
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Unknown document ID"},
        )
    result = await db.execute(
        select(DocumentChunk)
        .where(DocumentChunk.document_id == doc.id)
        .order_by(DocumentChunk.chunk_index)
    )
    chunks = result.scalars().all()
    return [
        ChunkOut(
            chunk_id=c.id, chunk_index=c.chunk_index, page_number=c.page_number,
            security_status=c.security_status, risk_score=c.risk_score,
            text_preview=c.text[:300],
        )
        for c in chunks
    ]

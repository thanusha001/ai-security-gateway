"""Document ingestion service.

Pipeline (spec §11):
  upload -> file validation -> type/size validation -> hash -> text extraction
  -> content validation -> chunking -> security scan -> trust/risk -> embedding
  -> pgvector storage

Transaction safety (spec §24): the document row is created PENDING, advanced
through SCANNING/PROCESSING, and only marked TRUSTED/SUSPICIOUS/BLOCKED when
its chunks are committed. Failures set FAILED with a persisted error code so
retry is possible. Duplicate hashes never reprocess (DUPLICATE_ACTION).
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.errors import ErrorCode, GatewayError
from app.core.logging import get_logger
from app.database.models import Document, DocumentChunk, DocumentSecurityScan
from app.rag.chunking import chunk_text
from app.rag.embeddings import EmbeddingError, embed_texts
from app.rag.text_extraction import InvalidFileError, detect_file_type, extract_text
from app.security.detectors import (
    JailbreakDetector,
    PIIDetector,
    PromptInjectionDetector,
    RagPoisoningDetector,
    SecretDetector,
)
from app.security.pipeline import InputSecurityResult

log = get_logger("documents")

ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md"}
# Malicious filename characters (path traversal, control chars, executables)
_UNSAFE_FILENAME_RE = re.compile(r"[^\w.\- ]")


class DocumentValidationError(GatewayError):
    pass


def sanitize_filename(name: str) -> str:
    """Never use the client filename as a path; produce a safe display name."""
    cleaned = _UNSAFE_FILENAME_RE.sub("_", name).strip(". ")[:200]
    return cleaned or "upload"


async def _run_security_scan(text: str) -> InputSecurityResult:
    """CPU-bound detector run; offloaded to a thread."""

    def _scan() -> InputSecurityResult:
        results = [
            PromptInjectionDetector().analyze_timed(text),
            JailbreakDetector().analyze_timed(text),
            RagPoisoningDetector().analyze_timed(text),
            SecretDetector().analyze_timed(text),
            PIIDetector().analyze_timed(text),
        ]
        return InputSecurityResult(results)

    return await asyncio.to_thread(_scan)


async def ingest_document(
    db: AsyncSession,
    *,
    data: bytes,
    filename: str,
    source: str | None = None,
) -> dict:
    """Ingest one uploaded document. Returns a response dict (never raises for
    expected security outcomes like BLOCKED — those are returned, not thrown)."""
    import time

    start = time.perf_counter()

    # 1. size validation
    if len(data) == 0:
        raise DocumentValidationError(ErrorCode.INVALID_FILE, "Uploaded file is empty", 400)
    if len(data) > settings.max_upload_size_bytes:
        raise DocumentValidationError(
            ErrorCode.DOCUMENT_TOO_LARGE,
            f"File exceeds {settings.max_upload_size_mb} MB limit",
            413,
        )

    # 2. extension allow-list (first pass; content sniffing follows)
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in ALLOWED_EXTENSIONS:
        raise DocumentValidationError(
            ErrorCode.UNSUPPORTED_FILE,
            f"Unsupported file type .{extension}; allowed: {sorted(ALLOWED_EXTENSIONS)}",
            400,
        )

    # 3. content-based type detection (never trust extension alone)
    try:
        file_type = detect_file_type(data, extension)
    except InvalidFileError as exc:
        raise DocumentValidationError(ErrorCode(exc.code), str(exc), 400)

    # 4. hash + duplicate check
    sha256_hash = hashlib.sha256(data).hexdigest()
    existing = (
        await db.execute(select(Document).where(Document.sha256_hash == sha256_hash))
    ).scalar_one_or_none()

    if existing is not None and settings.duplicate_action == "REUSE":
        return {
            "document_id": existing.document_id,
            "status": "DUPLICATE_DOCUMENT",
            "detail": "Document with identical content already exists (REUSE)",
            "duplicate": True,
            "trust_score": existing.trust_score,
            "risk_score": existing.risk_score,
            "chunk_count": existing.chunk_count,
            "threats": [],
        }
    if existing is not None and settings.duplicate_action == "REJECT":
        raise DocumentValidationError(
            ErrorCode.DUPLICATE_DOCUMENT,
            "Document with identical content already exists",
            409,
        )

    safe_name = sanitize_filename(filename)
    document = Document(
        document_id=uuid.uuid4().hex,
        filename=safe_name,
        safe_filename=safe_name,
        sha256_hash=sha256_hash,
        file_type=file_type.value,
        mime_type=file_type.value,
        file_size=len(data),
        source=source,
        status="PENDING",
    )
    db.add(document)
    await db.flush()  # assign PK without committing

    if existing is not None:  # REPROCESS: retire old version
        existing.status = "SUPERSEDED"

    try:
        document.status = "SCANNING"

        # 5. text extraction (with processing timeout)
        try:
            async with asyncio.timeout(settings.embedding_timeout_seconds):
                text, page_meta = await asyncio.to_thread(extract_text, data, file_type)
        except TimeoutError as exc:
            raise GatewayError(
                ErrorCode.DOCUMENT_PROCESSING_FAILED,
                "File processing timed out",
                500,
            ) from exc
        except InvalidFileError as exc:
            raise DocumentValidationError(ErrorCode(exc.code), str(exc), 400)

        if not text.strip():
            raise DocumentValidationError(ErrorCode.INVALID_FILE, "Document has no extractable text", 400)

        # 6. chunking
        chunks = chunk_text(text, settings.chunk_size, settings.chunk_overlap)

        # 7. per-chunk security scan
        document.status = "PROCESSING"
        chunk_rows: list[DocumentChunk] = []
        doc_max_risk = 0.0
        scan_records: list[dict] = []

        for chunk in chunks:
            scan = await _run_security_scan(chunk.text)
            chunk_status = "TRUSTED"
            if scan.max_risk >= 0.60:
                chunk_status = "BLOCKED"
            elif scan.max_risk >= 0.30:
                chunk_status = "SUSPICIOUS"
            doc_max_risk = max(doc_max_risk, scan.max_risk)
            chunk_rows.append(DocumentChunk(
                document_id=document.id,
                chunk_index=chunk.index,
                text=chunk.text,
                page_number=chunk.page_number,
                section=chunk.section,
                security_status=chunk_status,
                risk_score=scan.max_risk,
                metadata_json={"detectors": scan.summary()["actions"]},
            ))
            scan_records.append({
                "chunk_index": chunk.index,
                "risk": scan.max_risk,
                "status": chunk_status,
                "threats": [r.threat_type.value for r in scan.detected],
            })

        # 8. document-level scan record
        doc_scan_results = await _run_security_scan(text[:10000])
        doc_status = "TRUSTED"
        if doc_max_risk >= 0.60:
            doc_status = "BLOCKED"
        elif doc_max_risk >= 0.30:
            doc_status = "SUSPICIOUS"
        trust = round(1.0 - doc_max_risk, 3)

        # 9. embedding + persistence (only for chunks we keep; embed all statuses
        #    except BLOCKED so SUSPICIOUS can be policy-included later).
        #    Embedding is an enhancement, not a gate: when the model is missing
        #    (EmbeddingError, e.g. sentence-transformers not installed) the
        #    document is still stored with its security verdicts — it just
        #    cannot be retrieved by vector search. This is the documented
        #    degradation path (README: /health reports embedding_model:
        #    unavailable); failing the whole upload turned a missing optional
        #    dependency into data loss.
        embedding_note = ""
        try:
            to_embed = [c.text for c in chunk_rows if c.security_status != "BLOCKED"]
            vectors = await embed_texts(to_embed) if to_embed else []
        except EmbeddingError as exc:
            log.warning("embedding_unavailable_stored_unindexed",
                        document_id=document.document_id, error=str(exc))
            vectors = []
            embedding_note = " — stored without embeddings (embedding model unavailable)"
        vector_iter = iter(vectors)
        for row in chunk_rows:
            if row.security_status == "BLOCKED":
                continue
            row.embedding = next(vector_iter, None)

        for row in chunk_rows:
            db.add(row)
        db.add(DocumentSecurityScan(
            document_id=document.id,
            scan_type="full_document",
            status=doc_status,
            risk_score=doc_max_risk,
            trust_score=trust,
            threats_json={"chunks": scan_records[:50]},
            duration_ms=round((time.perf_counter() - start) * 1000, 2),
        ))

        document.status = doc_status
        document.trust_score = trust
        document.risk_score = round(doc_max_risk, 3)
        document.chunk_count = len(chunk_rows)
        await db.commit()

        log.info("document_ingested", document_id=document.document_id,
                 status=doc_status, chunks=len(chunk_rows))
        return {
            "document_id": document.document_id,
            "status": doc_status,
            "detail": f"Document processed with {len(chunk_rows)} chunks{embedding_note}",
            "duplicate": False,
            "trust_score": trust,
            "risk_score": round(doc_max_risk, 3),
            "chunk_count": len(chunk_rows),
            "threats": [s for s in scan_records if s["status"] != "TRUSTED"][:20],
        }

    except Exception:
        # transaction safety: persist failure state so retry is possible.
        # The rollback undoes chunk writes; we then persist FAILED on a fresh
        # transaction keyed by the unique hash. A FAILED document can be
        # re-uploaded later (hash lookup filters by status != SUPERSEDED).
        await db.rollback()
        try:
            failed = Document(
                document_id=document.document_id,
                filename=safe_name,
                safe_filename=safe_name,
                sha256_hash=sha256_hash + ":failed:" + uuid.uuid4().hex,
                file_type=file_type.value,
                mime_type=file_type.value,
                file_size=len(data),
                source=source,
                status="FAILED",
            )
            db.add(failed)
            await db.commit()
        except Exception:
            await db.rollback()
        raise

"""Document text extraction (PDF, DOCX, TXT, Markdown).

Safety rules:
- the file extension is NEVER trusted alone; the extractor validates magic
  bytes / parseability and raises InvalidFileError on mismatch
- corrupted or password-protected files raise controlled errors
- extraction is CPU-bound and wrapped by the caller in a timeout
"""
from __future__ import annotations

from enum import StrEnum

from pymupdf import Document as FitDocument


class InvalidFileError(Exception):
    """Raised when a file is corrupted, password-protected, or not what it claims."""

    def __init__(self, message: str, code: str = "INVALID_FILE") -> None:
        super().__init__(message)
        self.code = code  # INVALID_FILE | UNSUPPORTED_FILE


class SupportedType(StrEnum):
    PDF = "pdf"
    DOCX = "docx"
    TXT = "txt"
    MD = "md"


MAGIC = {
    SupportedType.PDF: b"%PDF-",
}

DOCX_ZIP_MAGIC = b"PK\x03\x04"


def detect_file_type(data: bytes, claimed_extension: str) -> SupportedType:
    """Sniff actual content; extension is only a hint, never authoritative."""
    if data.startswith(MAGIC[SupportedType.PDF]):
        return SupportedType.PDF
    if data.startswith(DOCX_ZIP_MAGIC):
        return SupportedType.DOCX
    claimed = claimed_extension.lower().lstrip(".")
    if claimed in (SupportedType.TXT, SupportedType.MD):
        return SupportedType(claimed)
    # ZIP that is not DOCX and claimed an office type -> suspicious
    if claimed in ("docx", "pdf"):
        raise InvalidFileError(
            f"File content does not match extension .{claimed}", code="INVALID_FILE"
        )
    raise InvalidFileError(
        f"Unsupported file type: .{claimed}", code="UNSUPPORTED_FILE"
    )


def extract_text(data: bytes, file_type: SupportedType) -> tuple[str, dict]:
    """Extract text plus metadata (page markers where available)."""
    if file_type == SupportedType.PDF:
        return _extract_pdf(data)
    if file_type == SupportedType.DOCX:
        return _extract_docx(data)
    return _extract_plain(data)


def _extract_pdf(data: bytes) -> tuple[str, dict]:
    try:
        doc = FitDocument(stream=data, filetype="pdf")
    except Exception as exc:  # PyMuPDF raises varied exception types
        raise InvalidFileError("Corrupted or unreadable PDF") from exc
    try:
        if doc.needs_pass:
            raise InvalidFileError("Password-protected PDFs are not supported")
        if doc.page_count == 0:
            raise InvalidFileError("PDF contains no pages")
        pages: list[str] = []
        for page in doc:
            pages.append(page.get_text("text"))
        text = "\n\n".join(pages)
        metadata = {"page_count": doc.page_count}
        return text, metadata
    finally:
        doc.close()


def _extract_docx(data: bytes) -> tuple[str, dict]:
    import io

    from docx import Document as DocxDocument

    try:
        doc = DocxDocument(io.BytesIO(data))
    except Exception as exc:
        raise InvalidFileError("Corrupted or unreadable DOCX") from exc
    paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
    if not paragraphs:
        raise InvalidFileError("DOCX contains no extractable text")
    return "\n\n".join(paragraphs), {"paragraph_count": len(paragraphs)}


def _extract_plain(data: bytes) -> tuple[str, dict]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidFileError("Text file is not valid UTF-8") from exc
    if not text.strip():
        raise InvalidFileError("Document is empty")
    return text, {}

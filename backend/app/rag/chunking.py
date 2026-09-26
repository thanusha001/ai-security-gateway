"""Configurable text chunking with overlap.

CHUNK_SIZE / CHUNK_OVERLAP are configurable; page/section metadata is carried
into chunks when available so the UI can show "Chunk #17 — Page 4".
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Chunk:
    index: int
    text: str
    page_number: int | None = None
    section: str | None = None


def chunk_text(
    text: str,
    chunk_size: int,
    overlap: int,
    page_markers: list[tuple[int, int]] | None = None,
) -> list[Chunk]:
    """Split text into overlapping chunks.

    page_markers: optional list of (char_start, page_number) for PDFs.
    """
    if chunk_size <= overlap:
        raise ValueError("chunk_size must be greater than chunk_overlap")
    text = text.strip()
    if not text:
        return []

    chunks: list[Chunk] = []
    step = chunk_size - overlap
    for i, start in enumerate(range(0, len(text), step)):
        piece = text[start:start + chunk_size].strip()
        if not piece:
            continue
        page_number = None
        if page_markers:
            for marker_start, page in page_markers:
                if marker_start <= start:
                    page_number = page
                else:
                    break
        chunks.append(Chunk(index=len(chunks), text=piece, page_number=page_number))
        if start + chunk_size >= len(text):
            break
    return chunks

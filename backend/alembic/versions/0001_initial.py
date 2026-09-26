"""initial schema: all gateway tables

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-23

Creates every table from app.database.models via ORM metadata (initial
migration). pgvector extension + vector indexes are created explicitly.
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import text

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # pgvector extension (also created by bootstrap; idempotent)
    op.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))

    from app.database.models import Base

    Base.metadata.create_all(bind=op.get_bind())

    # ANN index for cosine similarity search on chunks
    op.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_chunks_embedding "
            "ON document_chunks USING hnsw (embedding vector_cosine_ops)"
        )
    )


def downgrade() -> None:
    from app.database.models import Base

    Base.metadata.drop_all(bind=op.get_bind())

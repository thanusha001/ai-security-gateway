"""ORM models — one class per table (spec §23)."""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config import settings
from app.database.base import Base, IDMixin, TimestampMixin, utcnow


def _uuid() -> str:
    return uuid.uuid4().hex


# --- Users -------------------------------------------------------------------
class User(Base, IDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="USER")  # ADMIN|USER|AUDITOR
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    requests: Mapped[list["GatewayRequest"]] = relationship(back_populates="user")


# --- Policies ------------------------------------------------------------------
class SecurityPolicy(Base, IDMixin, TimestampMixin):
    __tablename__ = "security_policies"
    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_policy_name_version"),
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    description: Mapped[str | None] = mapped_column(Text)
    configuration_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)


# --- Requests ------------------------------------------------------------------
class GatewayRequest(Base, IDMixin, TimestampMixin):
    __tablename__ = "requests"

    request_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    session_id: Mapped[str | None] = mapped_column(String(64), index=True)
    input_text: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(10), default="LOW", nullable=False)
    final_decision: Mapped[str | None] = mapped_column(String(20))
    policy_id: Mapped[int | None] = mapped_column(ForeignKey("security_policies.id", ondelete="SET NULL"))
    policy_version: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    total_latency_ms: Mapped[float | None] = mapped_column(Float)
    error_code: Mapped[str | None] = mapped_column(String(50))
    response_text: Mapped[str | None] = mapped_column(Text)  # redacted/allowed output

    user: Mapped[User | None] = relationship(back_populates="requests")


# --- Security events & threats ---------------------------------------------------
class SecurityEvent(Base, IDMixin, TimestampMixin):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_sec_events_request_stage", "request_id", "stage"),
        Index("ix_sec_events_created", "created_at"),
    )

    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    stage: Mapped[str] = mapped_column(String(50), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="completed")
    severity: Mapped[str | None] = mapped_column(String(10))
    confidence: Mapped[float | None] = mapped_column(Float)
    risk_score: Mapped[float | None] = mapped_column(Float)
    action: Mapped[str | None] = mapped_column(String(20))
    detector: Mapped[str | None] = mapped_column(String(50))
    detector_version: Mapped[str | None] = mapped_column(String(20))
    reason: Mapped[str | None] = mapped_column(Text)
    evidence_json: Mapped[dict | None] = mapped_column(JSON)
    latency_ms: Mapped[float | None] = mapped_column(Float)


class ThreatDetection(Base, IDMixin, TimestampMixin):
    __tablename__ = "threat_detections"

    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    security_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("security_events.id", ondelete="SET NULL"), index=True
    )
    threat_type: Mapped[str] = mapped_column(String(50), index=True, nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    detector: Mapped[str] = mapped_column(String(50), nullable=False)
    evidence_json: Mapped[dict | None] = mapped_column(JSON)


# --- Documents & chunks ------------------------------------------------------------
class DocumentStatus(StrEnum):
    PENDING = "PENDING"
    SCANNING = "SCANNING"
    PROCESSING = "PROCESSING"
    TRUSTED = "TRUSTED"
    SUSPICIOUS = "SUSPICIOUS"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"


class Document(Base, IDMixin, TimestampMixin):
    __tablename__ = "documents"

    document_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    safe_filename: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    sha256_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    file_type: Mapped[str] = mapped_column(String(20), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default="PENDING", index=True, nullable=False)
    trust_score: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    chunk_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    chunks: Mapped[list["DocumentChunk"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )
    scans: Mapped[list["DocumentSecurityScan"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


class DocumentChunk(Base, IDMixin, TimestampMixin):
    __tablename__ = "document_chunks"
    __table_args__ = (
        Index("ix_chunks_doc_index", "document_id", "chunk_index"),
        Index("ix_chunks_security_status", "security_status"),
    )

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(settings.embedding_dimension))
    page_number: Mapped[int | None] = mapped_column(Integer)
    section: Mapped[str | None] = mapped_column(String(255))
    security_status: Mapped[str] = mapped_column(String(20), default="TRUSTED", nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    metadata_json: Mapped[dict | None] = mapped_column(JSON)

    document: Mapped[Document] = relationship(back_populates="chunks")


class DocumentSecurityScan(Base, IDMixin, TimestampMixin):
    __tablename__ = "document_security_scans"

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)  # full_document | per_chunk
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    trust_score: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    threats_json: Mapped[dict | None] = mapped_column(JSON)
    duration_ms: Mapped[float | None] = mapped_column(Float)

    document: Mapped[Document] = relationship(back_populates="scans")


class RetrievalEvent(Base, IDMixin, TimestampMixin):
    __tablename__ = "retrieval_events"

    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    document_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    chunk_id: Mapped[int] = mapped_column(Integer, nullable=False)
    similarity: Mapped[float | None] = mapped_column(Float)
    included: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exclusion_reason: Mapped[str | None] = mapped_column(String(255))
    security_status: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


# --- LLM observability --------------------------------------------------------------
class LLMRequest(Base, IDMixin, TimestampMixin):
    __tablename__ = "llm_requests"

    request_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    provider: Mapped[str] = mapped_column(String(30), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    total_tokens: Mapped[int | None] = mapped_column(Integer)
    token_count_source: Mapped[str | None] = mapped_column(String(20))  # exact|estimated|unavailable
    ttft_ms: Mapped[float | None] = mapped_column(Float)
    generation_latency_ms: Mapped[float | None] = mapped_column(Float)
    tokens_per_second: Mapped[float | None] = mapped_column(Float)
    context_length: Mapped[int | None] = mapped_column(Integer)
    temperature: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(20), default="completed", nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(30))


class LLMResponse(Base, IDMixin, TimestampMixin):
    __tablename__ = "llm_responses"

    llm_request_id: Mapped[int] = mapped_column(
        ForeignKey("llm_requests.id", ondelete="CASCADE"), index=True, nullable=False
    )
    response_text: Mapped[str] = mapped_column(Text, nullable=False)
    security_status: Mapped[str] = mapped_column(String(20), default="ALLOW", nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


# --- Audit & rate limiting -----------------------------------------------------------
class AuditLog(Base, IDMixin, TimestampMixin):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_created", "created_at"),)

    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    details_json: Mapped[dict | None] = mapped_column(JSON)
    ip_address: Mapped[str | None] = mapped_column(String(45))


class RateLimitEvent(Base, IDMixin, TimestampMixin):
    __tablename__ = "rate_limit_events"

    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    endpoint: Mapped[str] = mapped_column(String(100), nullable=False)
    client_identifier: Mapped[str] = mapped_column(String(128), nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

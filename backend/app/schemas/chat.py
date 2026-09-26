"""Chat API schemas."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=32000)
    session_id: str | None = Field(default=None, max_length=64)
    top_k: int | None = Field(default=None, ge=1, le=20)


class ChatResponse(BaseModel):
    request_id: str
    response: str | None = None
    final_decision: str
    risk_score: float
    risk_level: str
    policy_name: str | None
    policy_version: int | None
    total_latency_ms: float
    blocked_reason: str | None = None
    redacted: bool = False

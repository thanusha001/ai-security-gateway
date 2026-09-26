"""Policy API schemas."""
from __future__ import annotations

from pydantic import BaseModel, Field

from app.policy.engine import PolicyConfiguration


class PolicyCreate(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    description: str | None = None
    configuration: PolicyConfiguration


class PolicyUpdate(BaseModel):
    description: str | None = None
    configuration: PolicyConfiguration | None = None


class PolicyOut(BaseModel):
    id: int
    name: str
    version: int
    description: str | None
    configuration: dict
    is_active: bool
    created_at: str | None = None
    updated_at: str | None = None

"""Centralized application configuration.

All configuration comes from environment variables (12-factor). Secrets are
never hardcoded; see .env.example for documented defaults.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---
    app_env: Literal["development", "production"] = "development"
    debug: bool = True
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # --- Database ---
    database_url: str = "postgresql+asyncpg://gateway:gateway@localhost:5432/ai_security_gateway"
    db_echo: bool = False
    database_timeout_seconds: int = 10

    # --- Auth ---
    jwt_secret: str = "change-me-generate-a-real-secret-before-any-real-use"
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 480
    admin_email: str = "admin@example.local"
    admin_password: str = "change-me-admin-password"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # --- Rate limiting ---
    rate_limit_requests: int = 60
    rate_limit_window_seconds: int = 60
    rate_limit_upload_requests: int = 20
    rate_limit_upload_window_seconds: int = 60

    # --- LLM ---
    llm_provider: Literal["ollama", "openai", "anthropic"] = "ollama"
    llm_base_url: str = "http://localhost:11434"
    llm_model: str = "qwen3:4b"
    llm_context_length: int = 8192
    llm_temperature: float = 0.2
    llm_timeout_seconds: int = 120
    llm_max_output_tokens: int = 1024
    llm_security_classifier_enabled: bool = False
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None

    # --- Embeddings ---
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dimension: int = 384
    embedding_timeout_seconds: int = 60

    # --- RAG ---
    rag_enabled: bool = True
    chunk_size: int = 900
    chunk_overlap: int = 150
    top_k: int = 5
    min_similarity: float = 0.15
    max_upload_size_mb: int = 20
    duplicate_action: Literal["REUSE", "REJECT", "REPROCESS"] = "REUSE"

    # --- Risk thresholds (initial values; require empirical evaluation) ---
    risk_threshold_medium: float = 0.30
    risk_threshold_high: float = 0.60
    risk_threshold_critical: float = 0.80

    # --- Privacy / retention ---
    store_raw_prompts: bool = True
    store_raw_outputs: bool = True
    audit_retention_days: int = 90
    security_event_retention_days: int = 180

    @field_validator("cors_origins")
    @classmethod
    def _strip_cors(cls, v: str) -> str:
        return ",".join(o.strip() for o in v.split(",") if o.strip())

    @property
    def cors_origin_list(self) -> list[str]:
        return [o for o in self.cors_origins.split(",") if o]

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

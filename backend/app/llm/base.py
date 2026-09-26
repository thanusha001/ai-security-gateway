"""LLM provider abstraction.

The gateway never talks to a specific LLM vendor directly; it depends on the
LLMProvider interface. OllamaProvider is the initial implementation. Providers
are selected via LLM_PROVIDER env var; new vendors (openai, anthropic) can be
added without touching pipeline code.

Token accounting rule (spec §18): never fabricate token counts. If the
provider returns exact usage, use it with token_count_source="exact". If not,
estimate with a tokenizer and mark token_count_source="estimated".
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, AsyncIterator

import httpx


class TokenCountSource(StrEnum):
    EXACT = "exact"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"


@dataclass
class LLMUsage:
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    token_count_source: TokenCountSource


@dataclass
class LLMResult:
    text: str
    model: str
    provider: str
    usage: LLMUsage
    ttft_ms: float | None = None  # time to first token
    generation_latency_ms: float = 0.0
    tokens_per_second: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelInfo:
    provider: str
    model: str
    context_length: int
    temperature: float
    max_output_tokens: int


class LLMError(Exception):
    """Controlled LLM failure with a machine-readable error code."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code  # LLM_UNAVAILABLE | LLM_TIMEOUT | LLM_ERROR
        self.message = message
        self.details = details or {}


class LLMProvider(ABC):
    """Common interface: generate, stream, health_check, count_tokens, model_info."""

    provider_name: str = "abstract"

    def __init__(self, *, model: str, base_url: str, timeout_s: int,
                 temperature: float, max_output_tokens: int, context_length: int) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout_s = timeout_s
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.context_length = context_length

    @abstractmethod
    async def generate(self, prompt: str, *, system: str | None = None,
                       max_tokens: int | None = None) -> LLMResult:
        """Generate a completion. Implementations must enforce timeouts."""

    @abstractmethod
    async def stream(self, prompt: str, *, system: str | None = None,
                     max_tokens: int | None = None) -> AsyncIterator[str]:
        """Yield text chunks. The gateway buffers them for security scanning."""

    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if the provider is reachable and the model is usable."""

    @abstractmethod
    async def count_tokens(self, text: str) -> tuple[int, TokenCountSource]:
        """Return (token_estimate_or_count, source)."""

    @abstractmethod
    def model_info(self) -> ModelInfo:
        """Static configuration info about the active model."""

    async def generate_with_timing(self, prompt: str, *, system: str | None = None,
                                   max_tokens: int | None = None) -> LLMResult:
        start = time.perf_counter()
        result = await self.generate(prompt, system=system, max_tokens=max_tokens)
        result.generation_latency_ms = round((time.perf_counter() - start) * 1000, 2)
        if result.usage.output_tokens and result.generation_latency_ms > 0:
            result.tokens_per_second = round(
                result.usage.output_tokens / (result.generation_latency_ms / 1000), 1
            )
        return result


def estimate_tokens(text: str) -> int:
    """Cheap heuristic estimate (~4 chars/token). Marked 'estimated' upstream."""
    return max(1, len(text) // 4)


async def check_http_json(url: str, timeout_s: float) -> dict[str, Any] | None:
    """GET a JSON URL with timeout; returns None on any failure."""
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
    except (httpx.HTTPError, ValueError):
        return None

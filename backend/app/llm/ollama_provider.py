"""Ollama LLM provider (initial implementation).

Talks to the local Ollama daemon (default http://localhost:11434) using the
/api/chat and /api/tags endpoints. Ollama returns exact eval_count token
usage, so token_count_source is "exact" when available.
"""
from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx

from app.core.config import settings
from app.llm.base import (
    LLMError,
    LLMProvider,
    LLMResult,
    LLMUsage,
    ModelInfo,
    TokenCountSource,
    estimate_tokens,
)


class OllamaProvider(LLMProvider):
    provider_name = "ollama"

    def __init__(self) -> None:
        super().__init__(
            model=settings.llm_model,
            base_url=settings.llm_base_url,
            timeout_s=settings.llm_timeout_seconds,
            temperature=settings.llm_temperature,
            max_output_tokens=settings.llm_max_output_tokens,
            context_length=settings.llm_context_length,
        )

    async def generate(self, prompt: str, *, system: str | None = None,
                       max_tokens: int | None = None) -> LLMResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": ([{"role": "system", "content": system}] if system else [])
            + [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": max_tokens or self.max_output_tokens,
            },
        }
        start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=float(self.timeout_s)) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.TimeoutException as exc:
            raise LLMError("LLM_TIMEOUT", "LLM did not respond in time",
                           {"timeout_s": self.timeout_s}) from exc
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            raise LLMError("LLM_UNAVAILABLE", "LLM provider is unreachable",
                           {"base_url": self.base_url}) from exc
        except httpx.HTTPStatusError as exc:
            raise LLMError("LLM_ERROR", f"LLM returned HTTP {exc.response.status_code}",
                           {"status_code": exc.response.status_code}) from exc
        except json.JSONDecodeError as exc:
            raise LLMError("LLM_ERROR", "LLM returned malformed JSON") from exc

        latency_ms = round((time.perf_counter() - start) * 1000, 2)
        text = (data.get("message") or {}).get("content", "")

        input_tokens = data.get("prompt_eval_count")
        output_tokens = data.get("eval_count")
        if input_tokens is not None and output_tokens is not None:
            usage = LLMUsage(input_tokens, output_tokens,
                             input_tokens + output_tokens, TokenCountSource.EXACT)
        else:
            usage = LLMUsage(estimate_tokens(prompt), estimate_tokens(text),
                             None, TokenCountSource.ESTIMATED)

        return LLMResult(
            text=text,
            model=data.get("model", self.model),
            provider=self.provider_name,
            usage=usage,
            generation_latency_ms=latency_ms,
            tokens_per_second=(round(output_tokens / (latency_ms / 1000), 1)
                               if output_tokens and latency_ms > 0 else None),
            raw=data,
        )

    async def stream(self, prompt: str, *, system: str | None = None,
                     max_tokens: int | None = None) -> AsyncIterator[str]:
        """Yield chunks. The gateway buffers them before returning (spec §53)."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": ([{"role": "system", "content": system}] if system else [])
            + [{"role": "user", "content": prompt}],
            "stream": True,
            "options": {
                "temperature": self.temperature,
                "num_predict": max_tokens or self.max_output_tokens,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=float(self.timeout_s)) as client:
                async with client.stream("POST", f"{self.base_url}/api/chat", json=payload) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        piece = (chunk.get("message") or {}).get("content", "")
                        if piece:
                            yield piece
                        if chunk.get("done"):
                            break
        except httpx.TimeoutException as exc:
            raise LLMError("LLM_TIMEOUT", "LLM streaming timed out") from exc
        except httpx.HTTPError as exc:
            raise LLMError("LLM_UNAVAILABLE", "LLM provider is unreachable") from exc

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                if resp.status_code != 200:
                    return False
                data = resp.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                return any(m == self.model or m.split(":")[0] == self.model.split(":")[0]
                           for m in models)
        except (httpx.HTTPError, ValueError):
            return False

    async def count_tokens(self, text: str) -> tuple[int, TokenCountSource]:
        return estimate_tokens(text), TokenCountSource.ESTIMATED

    def model_info(self) -> ModelInfo:
        return ModelInfo(
            provider=self.provider_name,
            model=self.model,
            context_length=self.context_length,
            temperature=self.temperature,
            max_output_tokens=self.max_output_tokens,
        )

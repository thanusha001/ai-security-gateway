"""LLM provider factory.

Selects the configured provider. Only Ollama is implemented; openai/anthropic
raise a clear configuration error listing the supported providers, so adding
them later is a single file + one line here.
"""
from __future__ import annotations

from app.core.config import settings
from app.llm.base import LLMError, LLMProvider
from app.llm.ollama_provider import OllamaProvider

_PROVIDERS: dict[str, type[LLMProvider]] = {
    "ollama": OllamaProvider,
}


def get_llm_provider() -> LLMProvider:
    provider_cls = _PROVIDERS.get(settings.llm_provider)
    if provider_cls is None:
        raise LLMError(
            "LLM_ERROR",
            f"Unsupported LLM_PROVIDER '{settings.llm_provider}'. "
            f"Supported: {sorted(_PROVIDERS)}",
        )
    return provider_cls()

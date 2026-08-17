"""LLM Gateway – provider-independent interface for security analysis."""
from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from bbp_schemas.core import LLMRequest, LLMResponse, new_id


class LLMProvider(ABC):
    """Abstract LLM provider."""

    name: str = "base"

    @abstractmethod
    async def analyze(self, context: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    async def classify(self, finding: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    async def correlate(self, findings: list[dict[str, Any]]) -> dict[str, Any]: ...


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: str = "", model: str = "gpt-4o-mini"):
        self.api_key = api_key
        self.model = model

    async def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        # Placeholder: in production, call OpenAI API
        return {"provider": self.name, "model": self.model, "analysis": "pending"}

    async def classify(self, finding: dict[str, Any]) -> dict[str, Any]:
        return {"provider": self.name, "classification": "pending"}

    async def correlate(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {"provider": self.name, "correlations": []}


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str = "", model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model

    async def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        return {"provider": self.name, "model": self.model, "analysis": "pending"}

    async def classify(self, finding: dict[str, Any]) -> dict[str, Any]:
        return {"provider": self.name, "classification": "pending"}

    async def correlate(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {"provider": self.name, "correlations": []}


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3"):
        self.base_url = base_url
        self.model = model

    async def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        return {"provider": self.name, "model": self.model, "analysis": "pending"}

    async def classify(self, finding: dict[str, Any]) -> dict[str, Any]:
        return {"provider": self.name, "classification": "pending"}

    async def correlate(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {"provider": self.name, "correlations": []}


PROVIDER_REGISTRY: dict[str, type[LLMProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "ollama": OllamaProvider,
}


class LLMGateway:
    """Central LLM gateway with routing, fallback, cost tracking, and redaction."""

    def __init__(self, primary: str = "openai", fallbacks: Optional[list[str]] = None):
        self.providers: dict[str, LLMProvider] = {}
        self.primary = primary
        self.fallbacks = fallbacks or []
        self.total_tokens = 0
        self.total_cost = 0.0
        self.request_log: list[LLMRequest] = []

    def register_provider(self, name: str, provider: LLMProvider) -> None:
        self.providers[name] = provider

    async def analyze(self, context: dict[str, Any]) -> dict[str, Any]:
        """Analyze with primary provider, falling back if needed."""
        redacted = self._redact_secrets(context)
        providers_to_try = [self.primary] + self.fallbacks
        last_error = None

        for pname in providers_to_try:
            provider = self.providers.get(pname)
            if not provider:
                continue
            try:
                start = time.monotonic()
                result = await asyncio.wait_for(provider.analyze(redacted), timeout=30)
                latency = int((time.monotonic() - start) * 1000)
                self._log_request(pname, "analyze", latency)
                return result
            except Exception as e:
                last_error = e
                continue

        return {"error": str(last_error) if last_error else "No providers available"}

    async def classify(self, finding: dict[str, Any]) -> dict[str, Any]:
        provider = self.providers.get(self.primary)
        if not provider:
            return {"error": "No provider"}
        return await provider.classify(finding)

    async def correlate(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        provider = self.providers.get(self.primary)
        if not provider:
            return {"error": "No provider"}
        return await provider.correlate(findings)

    def _redact_secrets(self, data: dict[str, Any]) -> dict[str, Any]:
        """Redact potential secrets before sending to LLM."""
        import re
        redacted = {}
        secret_patterns = [
            re.compile(r'(?i)(api[_-]?key|token|secret|password|authorization)\s*[:=]\s*\S+'),
            re.compile(r'Bearer\s+\S+'),
        ]
        for k, v in data.items():
            if isinstance(v, str):
                val = v
                for pat in secret_patterns:
                    val = pat.sub("[REDACTED]", val)
                redacted[k] = val
            elif isinstance(v, dict):
                redacted[k] = self._redact_secrets(v)
            else:
                redacted[k] = v
        return redacted

    def _log_request(self, provider: str, method: str, latency_ms: int) -> None:
        req = LLMRequest(provider=provider, model=method)
        self.request_log.append(req)

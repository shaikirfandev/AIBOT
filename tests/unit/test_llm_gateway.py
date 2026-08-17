"""Tests for the LLM gateway."""
import pytest
from services_llm_gateway import LLMGateway, OpenAIProvider, AnthropicProvider, OllamaProvider


class TestLLMGateway:
    def test_register_provider(self):
        gw = LLMGateway()
        gw.register_provider("openai", OpenAIProvider())
        assert "openai" in gw.providers

    @pytest.mark.asyncio
    async def test_analyze(self):
        gw = LLMGateway(primary="openai")
        gw.register_provider("openai", OpenAIProvider())
        result = await gw.analyze({"data": "test"})
        assert result["provider"] == "openai"

    @pytest.mark.asyncio
    async def test_fallback(self):
        gw = LLMGateway(primary="missing", fallbacks=["openai"])
        gw.register_provider("openai", OpenAIProvider())
        result = await gw.analyze({"data": "test"})
        assert result["provider"] == "openai"

    @pytest.mark.asyncio
    async def test_no_providers(self):
        gw = LLMGateway(primary="missing")
        result = await gw.analyze({"data": "test"})
        assert "error" in result

    def test_redact_secrets(self):
        gw = LLMGateway()
        data = {"header": "Authorization: ******", "normal": "hello"}
        redacted = gw._redact_secrets(data)
        assert "sk-secret" not in redacted["header"]
        assert "[REDACTED]" in redacted["header"]
        assert redacted["normal"] == "hello"

    @pytest.mark.asyncio
    async def test_classify(self):
        gw = LLMGateway(primary="anthropic")
        gw.register_provider("anthropic", AnthropicProvider())
        result = await gw.classify({"title": "XSS"})
        assert result["provider"] == "anthropic"

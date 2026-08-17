"""Tests for the agent framework."""
import asyncio
import pytest
from bbp_schemas.core import AgentConfig, AgentStatus, ScopePolicy, ScopeRule
from bbp_scope import ScopeEngine
from bbp_common import (
    BaseAgent,
    ReconAgent,
    CrawlerAgent,
    create_agent,
    AGENT_REGISTRY,
)


def _scope_engine():
    scope = ScopeRule(domains=["example.com"], protocols=["https", "http"])
    policy = ScopePolicy(max_requests_per_second=100, max_total_requests=10000)
    return ScopeEngine(scope, policy)


class TestAgentFramework:
    def test_create_agent(self):
        agent = create_agent("recon", _scope_engine())
        assert agent.agent_type == "recon"

    def test_unknown_agent(self):
        with pytest.raises(ValueError, match="Unknown"):
            create_agent("nonexistent", _scope_engine())

    def test_registry_has_agents(self):
        assert "recon" in AGENT_REGISTRY
        assert "crawler" in AGENT_REGISTRY
        assert "api_security" in AGENT_REGISTRY

    @pytest.mark.asyncio
    async def test_agent_run_success(self):
        agent = create_agent("recon", _scope_engine())
        job = await agent.run("scan-1", {"target": "https://example.com"})
        assert job.status == AgentStatus.COMPLETED
        assert job.completed_at is not None

    @pytest.mark.asyncio
    async def test_agent_scope_violation(self):
        agent = create_agent("recon", _scope_engine())
        job = await agent.run("scan-1", {"target": "https://evil.com"})
        assert job.status == AgentStatus.FAILED
        assert "Scope violation" in (job.error or "")

    @pytest.mark.asyncio
    async def test_agent_timeout(self):
        class SlowAgent(BaseAgent):
            agent_type = "slow"
            async def execute(self, context):
                await asyncio.sleep(10)
                return {}

        config = AgentConfig(agent_type="slow", timeout=1)
        agent = SlowAgent(config, _scope_engine())
        job = await agent.run("scan-1", {"target": "https://example.com"})
        assert job.status == AgentStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_agent_events_emitted(self):
        agent = create_agent("recon", _scope_engine())
        await agent.run("scan-1", {"target": "https://example.com"})
        assert len(agent.events) >= 2  # requested + completed

"""Base agent framework for the Bug Bounty Platform.

Every agent inherits from BaseAgent and must implement execute().
Agents run in isolated contexts and all actions pass through the ScopeEngine.
"""
from __future__ import annotations

import asyncio
import traceback
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from bbp_schemas.core import (
    AgentConfig,
    AgentJob,
    AgentStatus,
    Event,
    EventType,
    Finding,
    FindingCreate,
    new_id,
)
from bbp_scope import ScopeEngine, ScopeViolation


class BaseAgent(ABC):
    """Abstract base class for all security agents."""

    agent_type: str = "base"

    def __init__(self, config: AgentConfig, scope_engine: ScopeEngine):
        self.config = config
        self.scope = scope_engine
        self.findings: list[Finding] = []
        self.events: list[Event] = []
        self._cancelled = False

    @abstractmethod
    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        """Run the agent's primary objective. Must be implemented by subclasses."""
        ...

    async def run(self, scan_id: str, context: dict[str, Any]) -> AgentJob:
        """Lifecycle wrapper: creates job, runs execute, handles errors."""
        job = AgentJob(
            scan_id=scan_id,
            agent_type=self.agent_type,
            status=AgentStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        self._emit(scan_id, EventType.TEST_REQUESTED, {"agent": self.agent_type})

        try:
            result = await asyncio.wait_for(
                self.execute(context),
                timeout=self.config.timeout,
            )
            job.status = AgentStatus.COMPLETED
            job.result = result or {}
            self._emit(scan_id, EventType.TEST_COMPLETED, {"agent": self.agent_type, "findings": len(self.findings)})
        except asyncio.TimeoutError:
            job.status = AgentStatus.TIMEOUT
            job.error = f"Agent timed out after {self.config.timeout}s"
            self._emit(scan_id, EventType.AGENT_FAILED, {"agent": self.agent_type, "error": job.error})
        except ScopeViolation as exc:
            job.status = AgentStatus.FAILED
            job.error = f"Scope violation: {exc}"
            self._emit(scan_id, EventType.AGENT_FAILED, {"agent": self.agent_type, "error": job.error})
        except Exception as exc:
            job.status = AgentStatus.FAILED
            job.error = traceback.format_exc()
            self._emit(scan_id, EventType.AGENT_FAILED, {"agent": self.agent_type, "error": str(exc)})

        job.completed_at = datetime.now(timezone.utc)
        return job

    def cancel(self) -> None:
        self._cancelled = True

    def check_target(self, url: str) -> None:
        """Convenience: enforce scope for a URL."""
        self.scope.check_target(url)

    def add_finding(self, finding: FindingCreate) -> Finding:
        f = Finding(**finding.model_dump())
        self.findings.append(f)
        return f

    def _emit(self, scan_id: str, event_type: EventType, data: dict) -> None:
        self.events.append(Event(scan_id=scan_id, event_type=event_type, data=data))


class ReconAgent(BaseAgent):
    agent_type = "recon"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        target = context.get("target", "")
        self.check_target(target)
        # Placeholder: real impl would run subfinder, amass, dns enum, etc.
        return {"assets_discovered": 0, "target": target}


class CrawlerAgent(BaseAgent):
    agent_type = "crawler"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        target = context.get("target", "")
        self.check_target(target)
        return {"urls_discovered": 0, "target": target}


class APISecurityAgent(BaseAgent):
    agent_type = "api_security"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        target = context.get("target", "")
        self.check_target(target)
        return {"endpoints_tested": 0, "target": target}


class BrowserAgent(BaseAgent):
    agent_type = "browser"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        target = context.get("target", "")
        self.check_target(target)
        return {"pages_visited": 0, "target": target}


class InjectionDetectionAgent(BaseAgent):
    agent_type = "injection"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        target = context.get("target", "")
        self.check_target(target)
        return {"tests_run": 0, "target": target}


class AuthorizationAgent(BaseAgent):
    agent_type = "authorization"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        target = context.get("target", "")
        self.check_target(target)
        return {"checks_performed": 0, "target": target}


class SecurityHeaderAgent(BaseAgent):
    agent_type = "security_headers"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        target = context.get("target", "")
        self.check_target(target)
        return {"headers_checked": 0, "target": target}


class EvidenceValidationAgent(BaseAgent):
    agent_type = "evidence_validation"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        finding_id = context.get("finding_id", "")
        return {"finding_id": finding_id, "validated": False}


class RegressionAgent(BaseAgent):
    agent_type = "regression"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        regression_test_id = context.get("regression_test_id", "")
        return {"regression_test_id": regression_test_id, "status": "pending"}


class LLMSecurityAnalyst(BaseAgent):
    agent_type = "llm_security"

    async def execute(self, context: dict[str, Any]) -> dict[str, Any]:
        return {"analysis": "pending", "findings_reviewed": 0}


# Registry
AGENT_REGISTRY: dict[str, type[BaseAgent]] = {
    "recon": ReconAgent,
    "crawler": CrawlerAgent,
    "api_security": APISecurityAgent,
    "browser": BrowserAgent,
    "injection": InjectionDetectionAgent,
    "authorization": AuthorizationAgent,
    "security_headers": SecurityHeaderAgent,
    "evidence_validation": EvidenceValidationAgent,
    "regression": RegressionAgent,
    "llm_security": LLMSecurityAnalyst,
}


def create_agent(agent_type: str, scope_engine: ScopeEngine, **kwargs: Any) -> BaseAgent:
    """Factory: instantiate an agent by type."""
    cls = AGENT_REGISTRY.get(agent_type)
    if cls is None:
        raise ValueError(f"Unknown agent type: {agent_type}. Available: {list(AGENT_REGISTRY)}")
    config = AgentConfig(agent_type=agent_type, **kwargs)
    return cls(config, scope_engine)

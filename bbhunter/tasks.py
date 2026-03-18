"""
Celery Task Definitions for BBHunter
======================================

Provides async task wrappers around the core engines so that:
- ``docker-compose.yml`` worker service can run: ``celery -A bbhunter.tasks worker``
- Long-running scans can be dispatched via the dashboard REST API
- Each task respects SafetyGate authorization + timeout
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from celery import Celery

from bbhunter.config import get_config

_cfg = get_config()

# ── Celery App ───────────────────────────────────────────────────────────

app = Celery(
    "bbhunter",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_soft_time_limit=_cfg.pipeline.step_timeout,
    task_time_limit=_cfg.pipeline.step_timeout + 60,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)


# ── Helper ───────────────────────────────────────────────────────────────

def _run(coro):
    """Run an async coroutine inside a Celery worker."""
    return asyncio.run(coro)


# ── Tasks ────────────────────────────────────────────────────────────────

@app.task(name="bbhunter.recon", bind=True, max_retries=2, default_retry_delay=30)
def run_recon(self, domain: str) -> dict[str, Any]:
    """Run full reconnaissance against *domain*."""
    from bbhunter.engines.recon.engine import ReconEngine
    from bbhunter.safety import get_safety_gate

    get_safety_gate().check(domain, action="recon")
    engine = ReconEngine()
    result = _run(engine.run(domain))
    return result.to_serializable()


@app.task(name="bbhunter.surface", bind=True, max_retries=2, default_retry_delay=30)
def run_surface(self, domain: str, subdomains: list[str] | None = None) -> dict[str, Any]:
    """Map attack surface for *domain*."""
    from bbhunter.engines.surface.engine import SurfaceMappingEngine
    from bbhunter.safety import get_safety_gate

    get_safety_gate().check(domain, action="surface_mapping")
    engine = SurfaceMappingEngine()
    result = _run(engine.run(domain, subdomains or []))
    return result.to_serializable()


@app.task(name="bbhunter.scan", bind=True, max_retries=1, default_retry_delay=60)
def run_scan(
    self,
    domain: str,
    endpoints: list[dict] | None = None,
    scanners: list[str] | None = None,
) -> dict[str, Any]:
    """Run vulnerability scanner against *domain*."""
    from bbhunter.engines.scanner.engine import VulnerabilityScanner
    from bbhunter.models import Endpoint
    from bbhunter.safety import get_safety_gate

    get_safety_gate().check(domain, action="vulnerability_scan")
    engine = VulnerabilityScanner()
    ep_models = [Endpoint(**e) for e in (endpoints or [])]
    result = _run(engine.run(domain, ep_models, scanners=scanners))
    return result.to_serializable()


@app.task(name="bbhunter.analysis", bind=True)
def run_analysis(self, vulnerabilities: list[dict]) -> dict[str, Any]:
    """Analyse and de-duplicate a set of findings."""
    from bbhunter.engines.analysis.engine import AnalysisEngine
    from bbhunter.models import Vulnerability

    vuln_models = [Vulnerability(**v) for v in vulnerabilities]
    engine = AnalysisEngine()
    result = _run(engine.run(vuln_models))
    # AnalysisEngine.run() returns dict[str, Any] already — but verified_vulnerabilities
    # are Pydantic models; serialise them for the Celery JSON backend.
    if isinstance(result, dict):
        verified = result.get("verified_vulnerabilities", [])
        if verified and hasattr(verified[0], "model_dump"):
            result["verified_vulnerabilities"] = [v.model_dump() for v in verified]
        chains = result.get("exploit_chains", [])
        if chains and hasattr(chains[0], "model_dump"):
            result["exploit_chains"] = [c.model_dump() for c in chains]
    return result


@app.task(name="bbhunter.full_pipeline", bind=True, max_retries=0)
def run_full_pipeline(self, domain: str) -> dict[str, Any]:
    """Execute the complete pipeline: recon → surface → scan → analysis → report."""
    from bbhunter.engines.recon.engine import ReconEngine
    from bbhunter.engines.surface.engine import SurfaceMappingEngine
    from bbhunter.engines.scanner.engine import VulnerabilityScanner
    from bbhunter.engines.analysis.engine import AnalysisEngine
    from bbhunter.engines.reporting.engine import ReportEngine
    from bbhunter.safety import get_safety_gate

    get_safety_gate().check(domain, action="full_pipeline")

    # Phase 1 – Recon
    self.update_state(state="PROGRESS", meta={"phase": "recon"})
    recon = _run(ReconEngine().run(domain))
    subdomains = recon.get("subdomains", [])

    # Phase 2 – Surface
    self.update_state(state="PROGRESS", meta={"phase": "surface"})
    surface = _run(SurfaceMappingEngine().run(domain, subdomains))
    endpoints = surface.get("endpoints", [])            # list[Endpoint] models

    # Phase 3 – Scan
    self.update_state(state="PROGRESS", meta={"phase": "scanning"})
    scan_result = _run(VulnerabilityScanner().run(domain, endpoints))
    vulns = scan_result.get("vulnerabilities", [])      # list[Vulnerability] models

    # Phase 4 – Analysis
    self.update_state(state="PROGRESS", meta={"phase": "analysis"})
    analysis = _run(AnalysisEngine().run(vulns))
    verified = analysis.get("verified_vulnerabilities", vulns) if isinstance(analysis, dict) else vulns
    chains = analysis.get("exploit_chains", []) if isinstance(analysis, dict) else []

    # Phase 5 – Report
    self.update_state(state="PROGRESS", meta={"phase": "reporting"})
    report = ReportEngine().generate_all_reports(domain, verified, chains, analysis or {})

    return {
        "domain": domain,
        "subdomains": len(subdomains),
        "endpoints": len(endpoints),
        "vulnerabilities": len(verified) if isinstance(verified, list) else 0,
        "report": report,
    }

"""Scans API with SSE event stream."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from bbp_schemas.core import (
    AgentConfig,
    Event,
    EventType,
    Scan,
    ScanCreate,
    ScanStatus,
    ScopePolicy,
)
from bbp_common import AGENT_REGISTRY, ScopeEngine, create_agent

from app.services.database import get_store

router = APIRouter(tags=["scans"])


@router.post("/scans", response_model=Scan)
async def create_scan(body: ScanCreate):
    programs = get_store("programs")
    if body.program_id not in programs:
        raise HTTPException(404, "Program not found")

    program = programs[body.program_id]

    # Validate target against scope
    scope_engine = ScopeEngine(program.scope, program.policy)
    try:
        scope_engine.check_target(body.target)
    except Exception as exc:
        raise HTTPException(403, f"Target not in scope: {exc}")

    scan = Scan(**body.model_dump())
    get_store("scans")[scan.id] = scan

    # Emit scan event
    event = Event(scan_id=scan.id, event_type=EventType.SCAN_REQUESTED, data={"target": body.target})
    get_store("events")[event.id] = event

    # Launch agents asynchronously
    asyncio.create_task(_run_scan(scan, program))

    return scan


async def _run_scan(scan: Scan, program) -> None:
    """Run agents in parallel for a scan."""
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)

    scope_engine = ScopeEngine(program.scope, program.policy)
    context = {"target": scan.target, "scan_id": scan.id, "program_id": program.id}

    agent_types = ["recon", "crawler", "api_security", "security_headers"]
    agents = []
    for at in agent_types:
        try:
            agent = create_agent(at, scope_engine)
            agents.append(agent)
        except ValueError:
            pass

    # Run in parallel
    jobs = await asyncio.gather(
        *[a.run(scan.id, context) for a in agents],
        return_exceptions=True,
    )

    job_store = get_store("agent_jobs")
    event_store = get_store("events")
    finding_store = get_store("findings")

    for i, job in enumerate(jobs):
        if isinstance(job, Exception):
            continue
        job_store[job.id] = job
        # Collect events and findings from agent
        agent = agents[i]
        for ev in agent.events:
            event_store[ev.id] = ev
        for f in agent.findings:
            finding_store[f.id] = f
            scan.findings_count += 1

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now(timezone.utc)

    event = Event(scan_id=scan.id, event_type=EventType.SCAN_COMPLETED, data={"findings": scan.findings_count})
    event_store[event.id] = event


@router.get("/scans")
async def list_scans():
    return list(get_store("scans").values())


@router.get("/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    scans = get_store("scans")
    if scan_id not in scans:
        raise HTTPException(404, "Scan not found")
    return scans[scan_id]


@router.get("/scans/{scan_id}/events")
async def get_scan_events(scan_id: str):
    events = get_store("events")
    return [e for e in events.values() if e.scan_id == scan_id]


@router.get("/scans/{scan_id}/agents")
async def get_scan_agents(scan_id: str):
    jobs = get_store("agent_jobs")
    return [j for j in jobs.values() if j.scan_id == scan_id]


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    findings = get_store("findings")
    return [f for f in findings.values() if f.scan_id == scan_id]


@router.get("/scans/{scan_id}/stream")
async def scan_event_stream(scan_id: str):
    """SSE stream for real-time scan events."""
    async def generate():
        seen = set()
        for _ in range(300):  # max 5 minutes
            events = get_store("events")
            for ev in events.values():
                if ev.scan_id == scan_id and ev.id not in seen:
                    seen.add(ev.id)
                    yield f"data: {ev.model_dump_json()}\n\n"
            scan = get_store("scans").get(scan_id)
            if scan and scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                yield f"data: {{\"type\": \"done\", \"status\": \"{scan.status.value}\"}}\n\n"
                break
            await asyncio.sleep(1)

    return StreamingResponse(generate(), media_type="text/event-stream")

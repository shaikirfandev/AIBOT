"""
Dashboard REST API
===================

FastAPI-based REST API exposing all BBHunter engines.
Provides endpoints for:
- Target management
- Scan orchestration
- Vulnerability viewing / triaging
- Report generation
- Learning feedback
- Real-time scan status via WebSocket
- API-key authentication middleware
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    BackgroundTasks,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from bbhunter.config import get_config
from bbhunter.exceptions import AuthorizationError, ScannerError
from bbhunter.logger import get_logger
from bbhunter.safety import get_safety_gate
from bbhunter.models import (
    Target, Asset, Endpoint, Vulnerability, ScanResult,
    Severity, VulnCategory, ScanStatus,
)
from bbhunter.engines.recon.engine import ReconEngine
from bbhunter.engines.surface.engine import SurfaceMappingEngine
from bbhunter.engines.scanner.engine import VulnerabilityScanner
from bbhunter.engines.analysis.engine import AnalysisEngine
from bbhunter.engines.payloads.engine import PayloadEngine
from bbhunter.engines.assistant.engine import ManualTestingAssistant
from bbhunter.engines.reporting.engine import ReportEngine
from bbhunter.engines.learning.engine import LearningEngine

logger = get_logger()
_cfg = get_config()

# ─── Security helpers ───────────────────────────────────────────────────

_DEFAULT_SECRET = "CHANGE-ME-IN-PRODUCTION"


def _get_api_key() -> str:
    """Return the active API key, auto-generating one if still the default."""
    key = _cfg.dashboard.secret_key
    if key == _DEFAULT_SECRET:
        # Auto-generate a secure key and warn loudly
        key = os.environ.get("BBHUNTER_API_KEY", secrets.token_urlsafe(32))
        logger.warning(
            "⚠️  Dashboard secret_key is the default. "
            "Set 'dashboard.secret_key' in config.yaml or BBHUNTER_API_KEY env var. "
            f"Auto-generated key for this session: {key}"
        )
    return key


_API_KEY = _get_api_key()
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str | None = Depends(_api_key_header)) -> str:
    """Dependency that enforces API-key authentication when enabled."""
    if not _cfg.dashboard.enable_auth:
        return "auth-disabled"
    if not api_key or not hmac.compare_digest(api_key, _API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key. Pass X-API-Key header.",
        )
    return api_key


# ─── FastAPI App ────────────────────────────────────────────────────────

app = FastAPI(
    title="BBHunter Dashboard",
    description="Bug Bounty Automation Suite – REST API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS: restrict to configured host instead of wildcard
_allowed_origins = [
    f"http://{_cfg.dashboard.host}:{_cfg.dashboard.port}",
    f"http://127.0.0.1:{_cfg.dashboard.port}",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Global State ───────────────────────────────────────────────────────

safety = get_safety_gate()
active_scans: dict[str, dict[str, Any]] = {}
ws_connections: list[WebSocket] = []


# ─── Request / Response Schemas ─────────────────────────────────────────

class TargetCreate(BaseModel):
    domain: str
    program: str = ""
    scope_patterns: list[str] = Field(default_factory=lambda: ["*"])


class ScanRequest(BaseModel):
    target_domain: str
    scan_type: str = "full"  # full | recon | surface | vuln | quick
    scanners: list[str] = Field(default_factory=list)


class FeedbackRequest(BaseModel):
    vulnerability_id: str
    is_true_positive: bool
    notes: str = ""


class PayloadRequest(BaseModel):
    category: str  # xss | sqli | ssrf
    context: str = "html"
    waf: str = ""


# ─── Helpers ────────────────────────────────────────────────────────────

async def broadcast(event: str, data: dict):
    """Broadcast event to all connected WebSocket clients."""
    msg = {"event": event, "data": data, "timestamp": datetime.now(timezone.utc).isoformat()}
    disconnected: list[WebSocket] = []
    for ws in ws_connections[:]:
        try:
            await ws.send_json(msg)
        except (WebSocketDisconnect, RuntimeError):
            disconnected.append(ws)
    for ws in disconnected:
        if ws in ws_connections:
            ws_connections.remove(ws)


# ─── Health ─────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# ─── Targets ────────────────────────────────────────────────────────────

@app.post("/api/targets", status_code=201)
async def create_target(body: TargetCreate, _key: str = Depends(verify_api_key)):
    """Register a new target for scanning."""
    try:
        safety.check(body.domain)
    except AuthorizationError as exc:
        raise HTTPException(403, detail=str(exc))

    from bbhunter.models import ScopeRule
    target = Target(
        domain=body.domain,
        scope=ScopeRule(include=body.scope_patterns),
        rules={"program": body.program},
    )
    return {"id": target.id, "domain": target.domain, "created": True}


# ─── Reconnaissance ────────────────────────────────────────────────────

@app.post("/api/recon")
async def start_recon(body: ScanRequest, background_tasks: BackgroundTasks, _key: str = Depends(verify_api_key)):
    """Launch passive + active recon against a target."""
    try:
        safety.check(body.target_domain)
    except AuthorizationError as exc:
        raise HTTPException(403, detail=str(exc))

    scan_id = f"recon-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    active_scans[scan_id] = {"status": "running", "type": "recon", "target": body.target_domain}

    async def _run():
        try:
            engine = ReconEngine()
            results = await engine.run(body.target_domain)
            active_scans[scan_id]["status"] = "complete"
            active_scans[scan_id]["results"] = {
                "subdomains": len(results.get("subdomains", [])),
                "urls": len(results.get("urls", [])),
                "dns_records": len(results.get("dns_records", [])),
            }
            await broadcast("recon_complete", active_scans[scan_id])
        except Exception as e:
            logger.error(f"Background task failed: {e}")
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)
            await broadcast("recon_error", active_scans[scan_id])

    background_tasks.add_task(_run)
    return {"scan_id": scan_id, "status": "started"}


# ─── Surface Mapping ───────────────────────────────────────────────────

@app.post("/api/surface")
async def start_surface_mapping(body: ScanRequest, background_tasks: BackgroundTasks, _key: str = Depends(verify_api_key)):
    """Map the attack surface of a target."""
    try:
        safety.check(body.target_domain)
    except AuthorizationError as exc:
        raise HTTPException(403, detail=str(exc))

    scan_id = f"surface-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    active_scans[scan_id] = {"status": "running", "type": "surface", "target": body.target_domain}

    async def _run():
        try:
            engine = SurfaceMappingEngine()
            results = await engine.run(body.target_domain, [])
            active_scans[scan_id]["status"] = "complete"
            active_scans[scan_id]["results"] = {
                "endpoints": len(results.get("endpoints", [])),
                "technologies": results.get("technologies", []),
                "waf_detected": results.get("waf", "none"),
            }
            await broadcast("surface_complete", active_scans[scan_id])
        except Exception as e:
            logger.error(f"Background task failed: {e}")
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)

    background_tasks.add_task(_run)
    return {"scan_id": scan_id, "status": "started"}


# ─── Vulnerability Scanner ─────────────────────────────────────────────

@app.post("/api/scan")
async def start_vulnerability_scan(body: ScanRequest, background_tasks: BackgroundTasks, _key: str = Depends(verify_api_key)):
    """Launch vulnerability scanner against discovered endpoints."""
    try:
        safety.check(body.target_domain)
    except AuthorizationError as exc:
        raise HTTPException(403, detail=str(exc))

    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    active_scans[scan_id] = {"status": "running", "type": "vuln_scan", "target": body.target_domain}

    async def _run():
        try:
            scanner = VulnerabilityScanner()
            results = await scanner.run(body.target_domain, [], scanners=body.scanners or None)
            active_scans[scan_id]["status"] = "complete"
            active_scans[scan_id]["results"] = {
                "vulnerabilities": len(results.get("vulnerabilities", [])),
                "critical": sum(
                    1 for v in results.get("vulnerabilities", [])
                    if v.get("severity") == "critical"
                ),
            }
            await broadcast("scan_complete", active_scans[scan_id])
        except Exception as e:
            logger.error(f"Background task failed: {e}")
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)

    background_tasks.add_task(_run)
    return {"scan_id": scan_id, "status": "started"}


# ─── Full Pipeline ──────────────────────────────────────────────────────

@app.post("/api/scan/full")
async def start_full_scan(body: ScanRequest, background_tasks: BackgroundTasks, _key: str = Depends(verify_api_key)):
    """Run complete pipeline: recon → surface → scan → analysis → report."""
    try:
        safety.check(body.target_domain)
    except AuthorizationError as exc:
        raise HTTPException(403, detail=str(exc))

    scan_id = f"full-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    active_scans[scan_id] = {
        "status": "running",
        "type": "full",
        "target": body.target_domain,
        "phase": "recon",
    }

    async def _run():
        try:
            domain = body.target_domain

            # Phase 1: Recon
            active_scans[scan_id]["phase"] = "recon"
            await broadcast("phase_change", {"scan_id": scan_id, "phase": "recon"})
            recon = ReconEngine()
            recon_results = await recon.run(domain)

            # Phase 2: Surface
            active_scans[scan_id]["phase"] = "surface"
            await broadcast("phase_change", {"scan_id": scan_id, "phase": "surface"})
            surface = SurfaceMappingEngine()
            subdomains = recon_results.get("subdomains", [])
            surface_results = await surface.run(domain, subdomains)

            # Phase 3: Vuln Scan
            active_scans[scan_id]["phase"] = "scanning"
            await broadcast("phase_change", {"scan_id": scan_id, "phase": "scanning"})
            scanner = VulnerabilityScanner()
            endpoints = surface_results.get("endpoints", [])
            scan_results = await scanner.run(domain, endpoints)

            # Phase 4: Analysis
            active_scans[scan_id]["phase"] = "analysis"
            await broadcast("phase_change", {"scan_id": scan_id, "phase": "analysis"})
            analyzer = AnalysisEngine()
            vulns = scan_results.get("vulnerabilities", [])
            analysis = await analyzer.run(vulns)

            # Phase 5: Report
            active_scans[scan_id]["phase"] = "reporting"
            await broadcast("phase_change", {"scan_id": scan_id, "phase": "reporting"})
            reporter = ReportEngine()
            verified_vulns = analysis.get("verified_vulnerabilities", vulns)
            chains = analysis.get("exploit_chains", [])
            report = reporter.generate_all_reports(
                domain, verified_vulns, chains, analysis
            )

            active_scans[scan_id]["status"] = "complete"
            active_scans[scan_id]["phase"] = "done"
            active_scans[scan_id]["results"] = {
                "subdomains_found": len(subdomains),
                "endpoints_mapped": len(endpoints),
                "vulnerabilities_count": len(verified_vulns),
                "verified_vulnerabilities": verified_vulns,
                "exploit_chains": chains,
                "report": report,
            }
            await broadcast("full_scan_complete", active_scans[scan_id])

        except Exception as e:
            logger.error(f"Background task failed: {e}")
            active_scans[scan_id]["status"] = "error"
            active_scans[scan_id]["error"] = str(e)
            await broadcast("scan_error", active_scans[scan_id])

    background_tasks.add_task(_run)
    return {"scan_id": scan_id, "status": "started"}


# ─── Scan Status ────────────────────────────────────────────────────────

@app.get("/api/scans")
async def list_scans():
    """List all active and completed scans."""
    return {"scans": active_scans}


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    """Get status of a specific scan."""
    if scan_id not in active_scans:
        raise HTTPException(404, detail="Scan not found")
    return active_scans[scan_id]


# ─── Analysis ───────────────────────────────────────────────────────────

@app.post("/api/analysis")
async def analyze_vulnerabilities(vulns: list[dict], _key: str = Depends(verify_api_key)):
    """Run intelligent analysis on a set of vulnerability findings."""
    # Convert raw dicts to Vulnerability model objects
    vuln_objects = []
    for v in vulns:
        try:
            vuln_objects.append(Vulnerability(**v))
        except Exception as exc:
            logger.debug(f"Vulnerability model construction failed, using fallback: {exc}")
            vuln_objects.append(Vulnerability(
                target_id=v.get("target_id", "unknown"),
                category=VulnCategory(v.get("category", "other")),
                severity=Severity(v.get("severity", "informational")),
                title=v.get("title", "Unknown"),
                url=v.get("url", ""),
                confidence=float(v.get("confidence", 0.5)),
            ))
    analyzer = AnalysisEngine()
    results = await analyzer.run(vuln_objects)
    return results


# ─── Payloads ───────────────────────────────────────────────────────────

@app.post("/api/payloads")
async def generate_payloads(body: PayloadRequest, _key: str = Depends(verify_api_key)):
    """Generate context-aware payloads."""
    engine = PayloadEngine()
    payloads = engine.generate(
        category=body.category,
        context=body.context,
        waf=body.waf or None,
    )
    return {"payloads": payloads, "count": len(payloads)}


# ─── Reports ───────────────────────────────────────────────────────────

@app.get("/api/reports/{scan_id}")
async def generate_report(scan_id: str, template: str = "hackerone"):
    """Generate a report for a completed scan."""
    if scan_id not in active_scans:
        raise HTTPException(404, detail="Scan not found")
    scan = active_scans[scan_id]
    if scan["status"] != "complete":
        raise HTTPException(400, detail="Scan not yet complete")

    reporter = ReportEngine()
    results = scan.get("results", {})
    report_data = results.get("report", [])
    if report_data:
        return {"report": report_data}
    # Fallback: re-generate from stored vulnerabilities
    vulns = results.get("vulnerabilities", [])
    if isinstance(vulns, list) and vulns:
        verified = results.get("verified_vulnerabilities", vulns)
        chains = results.get("exploit_chains", [])
        reports = reporter.generate_all_reports(
            scan["target"], verified, chains, results
        )
        return {"report": reports}
    return {"report": []}


# ─── Feedback / Learning ───────────────────────────────────────────────

@app.post("/api/feedback")
async def submit_feedback(body: FeedbackRequest, _key: str = Depends(verify_api_key)):
    """Submit TP / FP feedback to the learning engine."""
    engine = LearningEngine()
    engine.record_feedback(
        vulnerability=Vulnerability(
            id=body.vulnerability_id,
            target_id="feedback",
            title="",
            category=VulnCategory.OTHER,
            severity=Severity.INFORMATIONAL,
            url="",
        ),
        is_true_positive=body.is_true_positive,
        researcher_notes=body.notes,
    )
    return {"status": "recorded"}


@app.get("/api/learning/stats")
async def learning_stats():
    """Get learning module statistics."""
    engine = LearningEngine()
    return engine.get_statistics()


# ─── Assistant ──────────────────────────────────────────────────────────

@app.post("/api/assistant/vectors")
async def suggest_vectors(endpoint: dict, _key: str = Depends(verify_api_key)):
    """Get attack vector suggestions for an endpoint."""
    # Convert raw dict to Endpoint model
    try:
        ep = Endpoint(**endpoint)
    except Exception as exc:
        logger.debug(f"Endpoint model construction failed, using fallback: {exc}")
        ep = Endpoint(
            target_id=endpoint.get("target_id", "unknown"),
            url=endpoint.get("url", ""),
            method=endpoint.get("method", "GET"),
        )
    assistant = ManualTestingAssistant()
    return assistant.suggest_attack_vectors(ep)


@app.post("/api/assistant/decode")
async def decode_data(body: dict, _key: str = Depends(verify_api_key)):
    """Decode encoded data (base64, JWT, URL, hex)."""
    assistant = ManualTestingAssistant()
    return assistant.decode_data(body.get("data", ""))


# ─── WebSocket for Real-time Updates ───────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_connections.append(ws)
    try:
        while True:
            data = await ws.receive_text()
            # Clients can send ping / subscribe messages
            if data == "ping":
                await ws.send_json({"event": "pong"})
    except WebSocketDisconnect:
        ws_connections.remove(ws)


# ─── Dashboard HTML (SPA fallback) ─────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the dashboard SPA."""
    return DASHBOARD_HTML


# ─── Inline Dashboard SPA ──────────────────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BBHunter Dashboard</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --border: #30363d;
  --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950;
  --red: #f85149; --yellow: #d29922; --purple: #bc8cff;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background:var(--bg); color:var(--text); }
.header { background:var(--surface); border-bottom:1px solid var(--border);
           padding:16px 24px; display:flex; align-items:center; gap:16px; }
.header h1 { font-size:20px; color:var(--accent); }
.header .status { margin-left:auto; font-size:13px; color:var(--green); }
.container { display:grid; grid-template-columns:260px 1fr; min-height:calc(100vh - 56px); }
.sidebar { background:var(--surface); border-right:1px solid var(--border); padding:16px; }
.sidebar .nav-item { display:block; padding:10px 14px; margin:4px 0; border-radius:6px;
                     color:var(--text); text-decoration:none; cursor:pointer; font-size:14px; }
.sidebar .nav-item:hover, .sidebar .nav-item.active { background:#1f2937; color:var(--accent); }
.main { padding:24px; }
.card { background:var(--surface); border:1px solid var(--border); border-radius:8px;
        padding:20px; margin-bottom:16px; }
.card h3 { color:var(--accent); margin-bottom:12px; font-size:16px; }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; }
.stat { background:var(--surface); border:1px solid var(--border); border-radius:8px;
        padding:16px; text-align:center; }
.stat .value { font-size:28px; font-weight:700; color:var(--accent); }
.stat .label { font-size:12px; color:#8b949e; margin-top:4px; }
.btn { background:var(--accent); color:#fff; border:none; padding:8px 16px;
       border-radius:6px; cursor:pointer; font-size:14px; }
.btn:hover { opacity:0.9; }
.btn-danger { background:var(--red); }
input, select { background:var(--bg); border:1px solid var(--border); color:var(--text);
                padding:8px 12px; border-radius:6px; width:100%; margin-bottom:8px; }
.log { font-family:monospace; font-size:12px; background:var(--bg); border:1px solid var(--border);
       border-radius:6px; padding:12px; max-height:300px; overflow-y:auto; white-space:pre-wrap; }
.severity-critical { color:var(--red); font-weight:700; }
.severity-high { color:#f0883e; font-weight:700; }
.severity-medium { color:var(--yellow); }
.severity-low { color:var(--green); }
.severity-info { color:#8b949e; }
.phase-badge { display:inline-block; padding:2px 8px; border-radius:12px;
               font-size:11px; background:var(--accent); color:#fff; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--border); font-size:13px; }
th { color:#8b949e; font-weight:600; }
#live-log { color:var(--green); }
</style>
</head>
<body>
<div class="header">
  <h1>🎯 BBHunter</h1>
  <span style="font-size:13px;color:#8b949e">Bug Bounty Automation Suite</span>
  <span class="status" id="ws-status">● Connecting…</span>
</div>

<div class="container">
  <nav class="sidebar">
    <a class="nav-item active" data-page="overview">📊 Overview</a>
    <a class="nav-item" data-page="recon">🔍 Recon</a>
    <a class="nav-item" data-page="surface">🗺️ Surface Map</a>
    <a class="nav-item" data-page="scanner">⚡ Scanner</a>
    <a class="nav-item" data-page="vulns">🐛 Vulnerabilities</a>
    <a class="nav-item" data-page="payloads">💣 Payloads</a>
    <a class="nav-item" data-page="reports">📄 Reports</a>
    <a class="nav-item" data-page="learning">🧠 Learning</a>
    <a class="nav-item" data-page="settings">⚙️ Settings</a>
  </nav>

  <div class="main" id="content">
    <!-- Dynamic content rendered by JS -->
  </div>
</div>

<script>
const API = '';
let ws;

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(proto + '://' + location.host + '/ws');
  ws.onopen = () => { document.getElementById('ws-status').innerHTML = '● Connected'; };
  ws.onclose = () => {
    document.getElementById('ws-status').innerHTML = '<span style="color:var(--red)">● Disconnected</span>';
    setTimeout(connectWS, 3000);
  };
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    appendLog(msg.event + ': ' + JSON.stringify(msg.data));
  };
}
connectWS();

function appendLog(text) {
  const el = document.getElementById('live-log');
  if (el) { el.textContent += '\\n[' + new Date().toLocaleTimeString() + '] ' + text; el.scrollTop = el.scrollHeight; }
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  return res.json();
}

const pages = {
  overview: () => `
    <h2 style="margin-bottom:16px">Dashboard Overview</h2>
    <div class="stats" id="stats">
      <div class="stat"><div class="value" id="s-scans">-</div><div class="label">Active Scans</div></div>
      <div class="stat"><div class="value" id="s-vulns">-</div><div class="label">Vulnerabilities</div></div>
      <div class="stat"><div class="value" id="s-targets">-</div><div class="label">Targets</div></div>
      <div class="stat"><div class="value" id="s-learning">-</div><div class="label">Feedback Samples</div></div>
    </div>
    <div class="card" style="margin-top:16px">
      <h3>Live Activity</h3>
      <div class="log" id="live-log" style="min-height:200px">Waiting for events...</div>
    </div>`,

  recon: () => `
    <h2 style="margin-bottom:16px">🔍 Reconnaissance</h2>
    <div class="card">
      <h3>Launch Recon</h3>
      <input id="recon-target" placeholder="Target domain (e.g., example.com)">
      <button class="btn" onclick="startRecon()">Start Recon</button>
    </div>
    <div class="card"><h3>Results</h3><div id="recon-results" class="log">No results yet.</div></div>`,

  scanner: () => `
    <h2 style="margin-bottom:16px">⚡ Vulnerability Scanner</h2>
    <div class="card">
      <h3>Launch Scan</h3>
      <input id="scan-target" placeholder="Target domain">
      <select id="scan-type"><option value="full">Full Scan</option><option value="quick">Quick Scan</option></select>
      <button class="btn" onclick="startScan()">Start Scan</button>
    </div>
    <div class="card"><h3>Scan Log</h3><div id="scan-log" class="log">Waiting…</div></div>`,

  surface: () => `
    <h2 style="margin-bottom:16px">🗺️ Attack Surface Map</h2>
    <div class="card">
      <h3>Map Surface</h3>
      <input id="surface-target" placeholder="Target domain">
      <button class="btn" onclick="startSurface()">Map Surface</button>
    </div>
    <div class="card"><h3>Endpoints</h3><div id="surface-results" class="log">No data.</div></div>`,

  vulns: () => `
    <h2 style="margin-bottom:16px">🐛 Vulnerabilities</h2>
    <div class="card"><table><thead><tr><th>Severity</th><th>Category</th><th>URL</th><th>Confidence</th><th>Actions</th></tr></thead>
    <tbody id="vuln-table"><tr><td colspan="5">No vulnerabilities found yet.</td></tr></tbody></table></div>`,

  payloads: () => `
    <h2 style="margin-bottom:16px">💣 Payload Generator</h2>
    <div class="card">
      <h3>Generate Payloads</h3>
      <select id="payload-cat"><option value="xss">XSS</option><option value="sqli">SQLi</option><option value="ssrf">SSRF</option><option value="ssti">SSTI</option></select>
      <input id="payload-ctx" placeholder="Context (html, attribute, javascript)">
      <input id="payload-waf" placeholder="WAF (optional: cloudflare, akamai)">
      <button class="btn" onclick="genPayloads()">Generate</button>
    </div>
    <div class="card"><h3>Payloads</h3><div id="payload-list" class="log">Generate payloads above.</div></div>`,

  reports: () => `
    <h2 style="margin-bottom:16px">📄 Reports</h2>
    <div class="card">
      <h3>Generate Report</h3>
      <input id="report-scan" placeholder="Scan ID">
      <select id="report-tpl"><option value="hackerone">HackerOne</option><option value="bugcrowd">Bugcrowd</option><option value="executive">Executive</option></select>
      <button class="btn" onclick="genReport()">Generate</button>
    </div>`,

  learning: () => `
    <h2 style="margin-bottom:16px">🧠 Learning Module</h2>
    <div class="card"><h3>Statistics</h3><div id="learning-stats" class="log">Loading…</div></div>
    <div class="card">
      <h3>Submit Feedback</h3>
      <input id="fb-vuln" placeholder="Vulnerability ID">
      <select id="fb-tp"><option value="true">True Positive</option><option value="false">False Positive</option></select>
      <input id="fb-notes" placeholder="Notes">
      <button class="btn" onclick="submitFB()">Submit</button>
    </div>`,

  settings: () => `
    <h2 style="margin-bottom:16px">⚙️ Settings</h2>
    <div class="card"><h3>Configuration</h3><p>Edit <code>config.yaml</code> and <code>authorized_targets.yaml</code> to configure BBHunter.</p></div>`,
};

function navigate(page) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.querySelector('[data-page="'+page+'"]').classList.add('active');
  document.getElementById('content').innerHTML = pages[page]();
  if (page === 'overview') loadOverview();
  if (page === 'learning') loadLearning();
}

document.querySelectorAll('.nav-item').forEach(n => {
  n.addEventListener('click', () => navigate(n.dataset.page));
});

async function loadOverview() {
  try {
    const scans = await api('/api/scans');
    document.getElementById('s-scans').textContent = Object.keys(scans.scans || {}).length;
  } catch(e) {}
  try {
    const ls = await api('/api/learning/stats');
    document.getElementById('s-learning').textContent = ls.total_samples || 0;
  } catch(e) {}
}

async function loadLearning() {
  try {
    const s = await api('/api/learning/stats');
    document.getElementById('learning-stats').textContent = JSON.stringify(s, null, 2);
  } catch(e) {}
}

async function startRecon() {
  const t = document.getElementById('recon-target').value;
  const r = await api('/api/recon', {method:'POST', body:JSON.stringify({target_domain:t})});
  document.getElementById('recon-results').textContent = JSON.stringify(r, null, 2);
}

async function startScan() {
  const t = document.getElementById('scan-target').value;
  const st = document.getElementById('scan-type').value;
  const r = await api('/api/scan', {method:'POST', body:JSON.stringify({target_domain:t, scan_type:st})});
  document.getElementById('scan-log').textContent = JSON.stringify(r, null, 2);
}

async function startSurface() {
  const t = document.getElementById('surface-target').value;
  const r = await api('/api/surface', {method:'POST', body:JSON.stringify({target_domain:t})});
  document.getElementById('surface-results').textContent = JSON.stringify(r, null, 2);
}

async function genPayloads() {
  const cat = document.getElementById('payload-cat').value;
  const ctx = document.getElementById('payload-ctx').value || 'html';
  const waf = document.getElementById('payload-waf').value || '';
  const r = await api('/api/payloads', {method:'POST', body:JSON.stringify({category:cat,context:ctx,waf:waf})});
  document.getElementById('payload-list').textContent = (r.payloads || []).join('\\n');
}

async function genReport() {
  const sid = document.getElementById('report-scan').value;
  const tpl = document.getElementById('report-tpl').value;
  const r = await api('/api/reports/'+sid+'?template='+tpl);
  alert(JSON.stringify(r));
}

async function submitFB() {
  const vid = document.getElementById('fb-vuln').value;
  const tp = document.getElementById('fb-tp').value === 'true';
  const notes = document.getElementById('fb-notes').value;
  await api('/api/feedback', {method:'POST', body:JSON.stringify({vulnerability_id:vid,is_true_positive:tp,notes:notes})});
  alert('Feedback submitted');
}

navigate('overview');
</script>
</body>
</html>
"""

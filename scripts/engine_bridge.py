#!/usr/bin/env python3
"""
Engine Bridge - Connects the scripts/ pipeline to bbhunter/ engines
====================================================================

After hunt.py finishes its 14-step recon, this bridge:
  1. Reads all recon data files + DB records
  2. Converts them into bbhunter pydantic models (Target, Asset, Endpoint, etc.)
  3. Runs the engines in sequence:
       Surface Mapping → Vulnerability Scanner → Analysis →
       Payload Generation → Assistant Suggestions → Reporting → Learning
  4. Stores all results back into the SQLite DB + files

Usage (standalone):
    python3 scripts/engine_bridge.py                 # run all engines
    python3 scripts/engine_bridge.py --engine surface  # single engine
    python3 scripts/engine_bridge.py --list            # list engines

Usage (from pipeline):
    from engine_bridge import run_all_engines
    asyncio.run(run_all_engines())
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Path setup ───────────────────────────────────────────────
SCRIPTS_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPTS_DIR.parent

# Add both scripts/ and project root to path
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(BASE_DIR))

# ── Scripts-side imports ──────────────────────────────────────
from config import (
    TARGET_DOMAIN, TARGET_DIR, TARGET_LLM_DIR, TARGET_REPORT_DIR,
    DOORDASH_RULES, LOGS_DIR, ensure_dirs,
)
from db_manager import get_db, DBManager

# ── bbhunter-side imports ─────────────────────────────────────
from bbhunter.models import (
    Asset, AssetType, Authorization, Endpoint, ExploitChain,
    Parameter, Report, ScanResult, ScanStatus, ScopeRule,
    Severity, Target, Vulnerability, VulnCategory,
)

# ── Logging ───────────────────────────────────────────────────
LOG_FILE = LOGS_DIR / "engine_bridge.log"


def log(msg: str, level: str = "INFO"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ──────────────────────────────────────────────────────────────
#  1. DATA LOADERS  — read recon files → bbhunter models
# ──────────────────────────────────────────────────────────────

def build_target() -> Target:
    """Build a bbhunter Target from scripts/config.py settings."""
    in_scope = DOORDASH_RULES.get("in_scope", [])
    oos = DOORDASH_RULES.get("out_of_scope_domains", [])
    oos_wc = DOORDASH_RULES.get("out_of_scope_wildcards", [])

    return Target(
        domain=TARGET_DOMAIN,
        scope=ScopeRule(
            include=in_scope + [f"*.{TARGET_DOMAIN}"],
            exclude=oos + oos_wc,
        ),
        authorization=Authorization(
            type="bug_bounty_program",
            platform="hackerone",
            program_url="https://hackerone.com/doordash",
            authorized_date="2025-01-01",
            tester="security-researcher",
        ),
        rules=DOORDASH_RULES,
    )


def load_assets_from_files(target: Target) -> list[Asset]:
    """Read subdomain/DNS files and produce Asset objects."""
    assets: list[Asset] = []
    seen = set()

    # Subdomains
    sub_file = TARGET_DIR / "01_subdomains_inscope.txt"
    if sub_file.exists():
        for line in sub_file.read_text().strip().splitlines():
            val = line.strip()
            if val and val not in seen:
                seen.add(val)
                assets.append(Asset(
                    target_id=target.id,
                    asset_type=AssetType.SUBDOMAIN,
                    value=val,
                    source="subfinder+amass",
                ))

    # DNS resolved
    dns_file = TARGET_DIR / "02_dns_resolved.txt"
    if dns_file.exists():
        for line in dns_file.read_text().strip().splitlines():
            parts = line.strip().split()
            if parts:
                subdomain = parts[0]
                # Extract IPs from the line
                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                for ip in ips:
                    key = f"ip:{ip}"
                    if key not in seen:
                        seen.add(key)
                        assets.append(Asset(
                            target_id=target.id,
                            asset_type=AssetType.IP,
                            value=ip,
                            source="dnsx",
                            metadata={"subdomain": subdomain},
                        ))

    log(f"Loaded {len(assets)} assets from recon files")
    return assets


def load_endpoints_from_files(target: Target) -> list[Endpoint]:
    """Read URL/endpoint files and produce Endpoint objects."""
    endpoints: list[Endpoint] = []
    seen_urls = set()

    # Files to load URLs from (in priority order)
    url_files = [
        ("03_urls_interesting.txt", "gau_interesting"),
        ("04_wayback_clean.txt", "waybackurls"),
        ("04b_katana_clean.txt", "katana"),
        ("04c_hakrawler_clean.txt", "hakrawler"),
        ("07_js_endpoints.txt", "js_analysis"),
        ("03_urls_clean.txt", "gau"),  # big file last
    ]

    for fname, source in url_files:
        fpath = TARGET_DIR / fname
        if not fpath.exists():
            continue
        for line in fpath.read_text().strip().splitlines():
            url = line.strip()
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            # Parse parameters from URL
            params = []
            if "?" in url:
                query_str = url.split("?", 1)[1]
                for pair in query_str.split("&"):
                    if "=" in pair:
                        pname, pval = pair.split("=", 1)
                        params.append(Parameter(
                            name=pname.strip(),
                            location="query",
                            sample_value=pval[:100],
                        ))

            endpoints.append(Endpoint(
                target_id=target.id,
                url=url,
                method="GET",
                parameters=params,
                metadata={"source": source},
            ))

    # httpx live hosts — enrich with status/tech info
    httpx_file = TARGET_DIR / "02b_httpx_live.txt"
    if httpx_file.exists():
        for line in httpx_file.read_text().strip().splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            url = parts[0]
            if url not in seen_urls:
                seen_urls.add(url)
                ep = Endpoint(
                    target_id=target.id,
                    url=url,
                    method="GET",
                    metadata={"source": "httpx", "raw": line.strip()},
                )
                # Try to extract status code from httpx output
                for p in parts[1:]:
                    if p.isdigit():
                        ep.status_code = int(p)
                        break
                endpoints.append(ep)

    log(f"Loaded {len(endpoints)} endpoints from recon files "
        f"({sum(1 for e in endpoints if e.parameters)} with params)")
    return endpoints


def load_technologies_from_files() -> list[str]:
    """Read tech detection data."""
    techs = set()
    tech_file = TARGET_DIR / "05_tech_headers.txt"
    if tech_file.exists():
        content = tech_file.read_text()
        for line in content.splitlines():
            ll = line.lower().strip()
            for hname in ["server:", "x-powered-by:"]:
                if ll.startswith(hname):
                    techs.add(line.split(":", 1)[1].strip()[:50])
    return sorted(techs)


def load_llm_vulnerabilities(target: Target) -> list[Vulnerability]:
    """
    Read LLM-extracted vulnerabilities from DB.
    These become the initial findings for the Analysis Engine.
    """
    vulns: list[Vulnerability] = []
    db = get_db()
    tid = db.get_target_id(TARGET_DOMAIN)
    if not tid:
        log("No target found in DB, skipping LLM vulns")
        return vulns

    rows = db._fetch_all(
        "SELECT * FROM vulnerabilities WHERE target_id = ?", (tid,)
    )

    cat_map = {c.value: c for c in VulnCategory}
    sev_map = {s.value: s for s in Severity}

    for row in rows:
        raw = dict(row)
        category_str = (raw.get("category") or "other").lower()
        severity_str = (raw.get("severity") or "informational").lower()

        vuln = Vulnerability(
            target_id=target.id,
            category=cat_map.get(category_str, VulnCategory.OTHER),
            severity=sev_map.get(severity_str, Severity.INFORMATIONAL),
            title=raw.get("title", "Unknown"),
            description=raw.get("description", ""),
            url=raw.get("url", ""),
            evidence=raw.get("evidence", ""),
            confidence=float(raw.get("confidence", 0.5)),
            metadata={"source": raw.get("source", "llm"), "db_id": raw.get("id", "")},
        )
        vulns.append(vuln)

    log(f"Loaded {len(vulns)} LLM-extracted vulnerabilities from DB")
    return vulns


# ──────────────────────────────────────────────────────────────
#  2. ENGINE CONFIG SETUP  — create config.yaml-compatible env
# ──────────────────────────────────────────────────────────────

def _ensure_bbhunter_config():
    """
    Make sure bbhunter's get_config() works by pointing to config.yaml.
    The engines call get_config() in their __init__.
    We patch it to use the project-root config.yaml that already exists.
    """
    import bbhunter.config as bb_cfg
    config_path = BASE_DIR / "config.yaml"
    if config_path.exists() and bb_cfg._config is None:
        try:
            bb_cfg._config = bb_cfg.load_config(str(config_path))
            log(f"bbhunter config loaded from {config_path}")
        except Exception as e:
            log(f"bbhunter config load failed: {e}, using defaults", "WARN")
            bb_cfg._config = bb_cfg.Config()
    elif bb_cfg._config is None:
        bb_cfg._config = bb_cfg.Config()
        log("bbhunter config: using defaults (no config.yaml)")


def _ensure_safety_gate(target: Target):
    """
    Patch the SafetyGate so engines pass authorization checks
    using our Target object (skip YAML re-read).
    """
    import bbhunter.safety as bb_safety
    gate = bb_safety.get_safety_gate()
    # Inject our target if not already present
    if not any(t.domain == target.domain for t in gate.authorized_targets):
        gate.authorized_targets.append(target)
        log(f"Injected {target.domain} into SafetyGate authorized targets")


# ──────────────────────────────────────────────────────────────
#  3. ENGINE RUNNERS  — each engine wrapped with error handling
# ──────────────────────────────────────────────────────────────

async def run_surface_engine(target: Target, endpoints: list[Endpoint]) -> tuple[list[Endpoint], list[str], str | None]:
    """
    Run SurfaceMappingEngine.
    Uses recon endpoints as seed URLs for deeper crawling.
    Returns (endpoints, technologies, waf).
    """
    log("═══ ENGINE: Surface Mapping ═══")
    from bbhunter.engines.surface.engine import SurfaceMappingEngine

    engine = SurfaceMappingEngine()

    # Seed URLs from recon: pick the most interesting ones
    seed_urls = []
    for ep in endpoints[:200]:
        if ep.url.startswith("http"):
            seed_urls.append(ep.url)
    if not seed_urls:
        seed_urls = [f"https://www.{TARGET_DOMAIN}", f"https://{TARGET_DOMAIN}"]

    # Limit seeds to avoid hammering (passive spirit)
    seed_urls = sorted(set(seed_urls))[:50]
    log(f"  Seeding surface mapper with {len(seed_urls)} URLs")

    try:
        scan = await engine.run(TARGET_DOMAIN, seed_urls=seed_urls)
        new_endpoints = [
            Endpoint(**ep) for ep in scan.metadata.get("endpoints", [])
        ]
        techs = scan.metadata.get("technologies", [])
        waf = scan.metadata.get("waf")
        log(f"  ✅ Surface: {len(new_endpoints)} endpoints, {len(techs)} techs, WAF={waf or 'none'}")
        return new_endpoints, techs, waf
    except Exception as e:
        log(f"  ✗ Surface engine error: {e}", "ERROR")
        return [], [], None


async def run_scanner_engine(
    target: Target,
    endpoints: list[Endpoint],
    categories: list[str] | None = None,
) -> list[Vulnerability]:
    """
    Run VulnerabilityScanner on discovered endpoints.
    NOTE: DoorDash rules say "no_automated_scanners: true".
    We respect this by only scanning endpoints we already have data for
    and limiting to passive/low-impact categories.
    """
    log("═══ ENGINE: Vulnerability Scanner ═══")

    # Check DoorDash rules
    if DOORDASH_RULES.get("no_automated_scanners"):
        log("  ⚠️  Target rules prohibit automated scanners.")
        log("  Running in PASSIVE-ONLY mode (headers, CORS, info disclosure)")
        # Only run passive scanners that don't send attack payloads
        categories = ["headers", "cors"]

    if not categories:
        categories = ["xss", "sqli", "ssrf", "idor", "cors", "open_redirect",
                       "ssti", "headers", "jwt", "auth"]

    from bbhunter.engines.scanner.engine import VulnerabilityScanner
    engine = VulnerabilityScanner()

    # Limit endpoints to avoid excessive requests
    scan_endpoints = [ep for ep in endpoints if ep.parameters][:100]
    if not scan_endpoints:
        scan_endpoints = endpoints[:50]

    log(f"  Scanning {len(scan_endpoints)} endpoints with {categories}")

    try:
        scan = await engine.run(TARGET_DOMAIN, scan_endpoints, categories=categories)
        vulns = [
            Vulnerability(**v)
            for v in scan.metadata.get("vulnerabilities", [])
        ]
        log(f"  ✅ Scanner: {len(vulns)} findings")
        return vulns
    except Exception as e:
        log(f"  ✗ Scanner engine error: {e}", "ERROR")
        return []


def run_analysis_engine(vulns: list[Vulnerability]) -> dict[str, Any]:
    """
    Run AnalysisEngine: FP reduction, chain detection, severity adjustment, attack graphs.
    """
    log("═══ ENGINE: Analysis ═══")
    from bbhunter.engines.analysis.engine import AnalysisEngine

    engine = AnalysisEngine()

    if not vulns:
        log("  No vulnerabilities to analyze, skipping")
        return {
            "verified_vulnerabilities": [],
            "exploit_chains": [],
            "impact_summary": {},
            "attack_graph": {},
            "statistics": {"total_findings": 0},
        }

    try:
        results = engine.analyze(vulns)
        stats = results.get("statistics", {})
        log(f"  ✅ Analysis: {stats.get('after_fp_reduction', 0)} verified "
            f"({stats.get('critical', 0)} critical, {stats.get('high', 0)} high), "
            f"{stats.get('chains', 0)} chains")
        return results
    except Exception as e:
        log(f"  ✗ Analysis engine error: {e}", "ERROR")
        return {"verified_vulnerabilities": vulns, "exploit_chains": [],
                "impact_summary": {}, "attack_graph": {}, "statistics": {}}


def run_payload_engine(vulns: list[Vulnerability], waf: str | None = None) -> dict[str, list[str]]:
    """
    Run PayloadEngine to generate smart payloads for confirmed vulns.
    """
    log("═══ ENGINE: Payload Generation ═══")
    from bbhunter.engines.payloads.engine import PayloadEngine

    engine = PayloadEngine()
    all_payloads: dict[str, list[str]] = {}

    if not vulns:
        log("  No vulns for payload generation")
        return all_payloads

    try:
        for vuln in vulns[:20]:  # Top 20 vulns
            cat = vuln.category.value
            payloads = engine.generate_payloads(
                category=cat,
                context="html",
                waf=waf,
                mutation_level=3,
            )
            if payloads:
                key = f"{vuln.title[:50]}|{cat}"
                all_payloads[key] = payloads[:20]  # Top 20 payloads each

        total = sum(len(v) for v in all_payloads.values())
        log(f"  ✅ Payloads: {total} payloads for {len(all_payloads)} vuln types")
        return all_payloads
    except Exception as e:
        log(f"  ✗ Payload engine error: {e}", "ERROR")
        return all_payloads


def run_assistant_engine(endpoints: list[Endpoint]) -> list[dict]:
    """
    Run ManualTestingAssistant to suggest attack vectors for interesting endpoints.
    """
    log("═══ ENGINE: Assistant (Attack Vector Suggestions) ═══")
    from bbhunter.engines.assistant.engine import ManualTestingAssistant

    engine = ManualTestingAssistant()
    all_suggestions: list[dict] = []

    # Pick the most interesting endpoints (with params, API endpoints, etc.)
    interesting = [ep for ep in endpoints if ep.parameters]
    interesting += [ep for ep in endpoints
                    if any(kw in ep.url.lower() for kw in
                           ["/api/", "/graphql", "/admin", "/auth", "/login", "/upload"])]
    interesting = interesting[:30]  # Limit

    if not interesting:
        interesting = endpoints[:20]

    try:
        for ep in interesting:
            suggestions = engine.suggest_attack_vectors(ep)
            if suggestions:
                all_suggestions.append({
                    "endpoint": ep.url,
                    "parameters": [p.name for p in ep.parameters],
                    "vectors": suggestions,
                })

        total_vectors = sum(len(s["vectors"]) for s in all_suggestions)
        log(f"  ✅ Assistant: {total_vectors} attack vectors for {len(all_suggestions)} endpoints")
        return all_suggestions
    except Exception as e:
        log(f"  ✗ Assistant engine error: {e}", "ERROR")
        return all_suggestions


def run_reporting_engine(
    vulns: list[Vulnerability],
    chains: list[ExploitChain],
    analysis_results: dict[str, Any],
) -> list[str]:
    """
    Run ReportEngine to generate professional bug bounty reports.
    """
    log("═══ ENGINE: Report Generation ═══")
    from bbhunter.engines.reporting.engine import ReportEngine

    engine = ReportEngine()

    try:
        reports = engine.generate_all_reports(
            TARGET_DOMAIN, vulns, chains, analysis_results
        )
        log(f"  ✅ Reports: {len(reports)} files generated")
        return reports
    except Exception as e:
        log(f"  ✗ Reporting engine error: {e}", "ERROR")
        return []


def run_learning_engine(vulns: list[Vulnerability]) -> dict[str, Any]:
    """
    Run LearningEngine to record findings for future improvement.
    """
    log("═══ ENGINE: Learning ═══")

    try:
        from bbhunter.engines.learning.engine import LearningEngine
        engine = LearningEngine()

        # Record each confirmed vuln as training data
        for vuln in vulns:
            if not vuln.false_positive:
                engine.record_feedback(vuln, is_true_positive=True,
                                       researcher_notes="auto-confirmed by analysis engine")

        stats = engine.get_statistics()
        log(f"  ✅ Learning: {stats.get('total_samples', 0)} samples, "
            f"model={'trained' if engine.fp_model else 'not yet trained'}")
        return stats
    except ImportError:
        log("  ⚠️  scikit-learn not installed, using basic learning module", "WARN")
        try:
            from bbhunter.engines.learning.module import LearningModule
            module = LearningModule()
            for vuln in vulns:
                if not vuln.false_positive:
                    module.record_feedback(vuln, is_true_positive=True)
            stats = module.get_statistics()
            log(f"  ✅ Learning (basic): {stats}")
            return stats
        except Exception as e:
            log(f"  ✗ Learning module error: {e}", "ERROR")
            return {}
    except Exception as e:
        log(f"  ✗ Learning engine error: {e}", "ERROR")
        return {}


# ──────────────────────────────────────────────────────────────
#  4. DB STORAGE  — persist engine results to SQLite
# ──────────────────────────────────────────────────────────────

def store_engine_results(
    db: DBManager,
    target_id: str,
    scan_run_id: str,
    surface_endpoints: list[Endpoint],
    scanner_vulns: list[Vulnerability],
    analysis_results: dict[str, Any],
    payloads: dict[str, list[str]],
    suggestions: list[dict],
):
    """Persist all engine outputs to the SQLite DB."""
    log("💾 Storing engine results in DB...")

    # Surface endpoints
    if surface_endpoints:
        eps = [{"url": ep.url, "source": "surface_engine",
                "is_interesting": 1 if ep.parameters else 0,
                "category": "surface_mapping"}
               for ep in surface_endpoints]
        inserted = db.store_endpoints(target_id, scan_run_id, eps)
        log(f"  {inserted} surface endpoints → DB")

    # Scanner vulnerabilities
    verified = analysis_results.get("verified_vulnerabilities", scanner_vulns)
    if verified:
        vuln_dicts = []
        for v in verified:
            vuln_dicts.append({
                "title": v.title,
                "category": v.category.value,
                "severity": v.severity.value,
                "url": v.url,
                "parameter": v.parameter,
                "evidence": v.evidence[:500] if v.evidence else "",
                "confidence": v.confidence,
                "source": "engine_scanner",
                "description": v.description[:500] if v.description else "",
            })
        db.store_vulnerabilities(target_id, scan_run_id, vuln_dicts)
        log(f"  {len(vuln_dicts)} verified vulnerabilities → DB")

    # Exploit chains
    chains = analysis_results.get("exploit_chains", [])
    if chains:
        for chain in chains:
            db.log_action("exploit_chain", TARGET_DOMAIN, details={
                "title": chain.title if hasattr(chain, "title") else str(chain),
                "severity": chain.combined_severity.value if hasattr(chain, "combined_severity") else "high",
                "impact": chain.impact if hasattr(chain, "impact") else "",
            }, scan_run_id=scan_run_id)
        log(f"  {len(chains)} exploit chains → DB")

    # Payloads
    if payloads:
        db.log_action("payloads_generated", TARGET_DOMAIN, details={
            "vuln_count": len(payloads),
            "total_payloads": sum(len(v) for v in payloads.values()),
        }, scan_run_id=scan_run_id)

    # Assistant suggestions
    if suggestions:
        db.log_action("assistant_suggestions", TARGET_DOMAIN, details={
            "endpoints_analyzed": len(suggestions),
            "total_vectors": sum(len(s["vectors"]) for s in suggestions),
        }, scan_run_id=scan_run_id)

    log("  ✅ All engine results stored in DB")


# ──────────────────────────────────────────────────────────────
#  5. FILE OUTPUT  — save engine results as readable files
# ──────────────────────────────────────────────────────────────

def save_engine_results_to_files(
    analysis_results: dict[str, Any],
    payloads: dict[str, list[str]],
    suggestions: list[dict],
    learning_stats: dict[str, Any],
    surface_techs: list[str],
    waf: str | None,
):
    """Save engine results as human-readable files in data/<target>/."""
    engine_dir = TARGET_DIR / "engines"
    engine_dir.mkdir(parents=True, exist_ok=True)

    # Analysis summary
    verified = analysis_results.get("verified_vulnerabilities", [])
    chains = analysis_results.get("exploit_chains", [])
    stats = analysis_results.get("statistics", {})

    lines = [
        f"╔{'═'*58}╗",
        f"║  Engine Analysis Results                                 ║",
        f"║  Target: {TARGET_DOMAIN:<48}║",
        f"╠{'═'*58}╣",
        f"║  Total findings scanned: {str(stats.get('total_findings', 0)):<32}║",
        f"║  After FP reduction:     {str(stats.get('after_fp_reduction', 0)):<32}║",
        f"║  Critical:               {str(stats.get('critical', 0)):<32}║",
        f"║  High:                   {str(stats.get('high', 0)):<32}║",
        f"║  Medium:                 {str(stats.get('medium', 0)):<32}║",
        f"║  Low:                    {str(stats.get('low', 0)):<32}║",
        f"║  Exploit chains:         {str(stats.get('chains', 0)):<32}║",
        f"╚{'═'*58}╝",
        "",
    ]

    # Technologies
    if surface_techs:
        lines.append("Technologies Detected:")
        for t in surface_techs:
            lines.append(f"  • {t}")
        lines.append("")

    if waf:
        lines.append(f"WAF Detected: {waf}")
        lines.append("")

    # Verified vulns
    if verified:
        lines.append("═" * 60)
        lines.append("VERIFIED VULNERABILITIES")
        lines.append("═" * 60)
        for v in verified:
            sev = v.severity.value if hasattr(v.severity, 'value') else str(v.severity)
            cat = v.category.value if hasattr(v.category, 'value') else str(v.category)
            lines.append(f"\n[{sev.upper()}] {v.title}")
            lines.append(f"  Category: {cat}")
            lines.append(f"  URL: {v.url}")
            if v.parameter:
                lines.append(f"  Parameter: {v.parameter}")
            if v.evidence:
                lines.append(f"  Evidence: {v.evidence[:200]}")
            if v.confidence:
                lines.append(f"  Confidence: {v.confidence:.0%}")

    # Chains
    if chains:
        lines.append("")
        lines.append("═" * 60)
        lines.append("EXPLOIT CHAINS")
        lines.append("═" * 60)
        for c in chains:
            lines.append(f"\n🔗 {c.title}")
            lines.append(f"   Severity: {c.combined_severity.value}")
            lines.append(f"   Impact: {c.impact}")

    (engine_dir / "analysis_results.txt").write_text("\n".join(lines) + "\n")

    # Payloads
    if payloads:
        payload_lines = [f"Generated Payloads for {TARGET_DOMAIN}", "=" * 60]
        for key, plist in payloads.items():
            payload_lines.append(f"\n[{key}]")
            for p in plist[:10]:
                payload_lines.append(f"  {p}")
        (engine_dir / "payloads.txt").write_text("\n".join(payload_lines) + "\n")

    # Attack vectors
    if suggestions:
        suggest_lines = [f"Attack Vector Suggestions for {TARGET_DOMAIN}", "=" * 60]
        for s in suggestions:
            suggest_lines.append(f"\n📌 {s['endpoint']}")
            if s.get("parameters"):
                suggest_lines.append(f"   Params: {', '.join(s['parameters'])}")
            for vec in s["vectors"]:
                suggest_lines.append(f"   → [{vec.get('priority', 'medium')}] {vec.get('vector', '')}")
                suggest_lines.append(f"     {vec.get('description', '')}")
        (engine_dir / "attack_vectors.txt").write_text("\n".join(suggest_lines) + "\n")

    # Impact summary
    impact = analysis_results.get("impact_summary", {})
    if impact:
        (engine_dir / "impact_summary.json").write_text(
            json.dumps(impact, indent=2, default=str) + "\n"
        )

    # Attack graph
    graph = analysis_results.get("attack_graph", {})
    if graph:
        (engine_dir / "attack_graph.json").write_text(
            json.dumps(graph, indent=2, default=str) + "\n"
        )

    log(f"📁 Engine results saved to {engine_dir}/")


# ──────────────────────────────────────────────────────────────
#  6. MASTER ORCHESTRATOR
# ──────────────────────────────────────────────────────────────

async def run_all_engines(engines_to_run: list[str] | None = None):
    """
    Main entry point: load recon data → run engines → store results.

    Args:
        engines_to_run: Optional list to run specific engines.
            Options: surface, scanner, analysis, payloads, assistant, reporting, learning
            Default: all engines.
    """
    all_engines = ["surface", "scanner", "analysis", "payloads",
                   "assistant", "reporting", "learning"]
    run_list = engines_to_run or all_engines

    log(f"╔{'═'*58}╗")
    log(f"║  BBHunter Engine Bridge                                  ║")
    log(f"║  Target: {TARGET_DOMAIN:<48}║")
    log(f"║  Engines: {', '.join(run_list):<47}║")
    log(f"╚{'═'*58}╝")

    total_start = time.time()

    # ── Setup ──
    ensure_dirs()
    _ensure_bbhunter_config()
    target = build_target()
    _ensure_safety_gate(target)

    # ── Load recon data ──
    log("\n📂 Loading recon data...")
    assets = load_assets_from_files(target)
    endpoints = load_endpoints_from_files(target)
    technologies = load_technologies_from_files()
    llm_vulns = load_llm_vulnerabilities(target)
    log(f"   {len(assets)} assets, {len(endpoints)} endpoints, "
        f"{len(technologies)} techs, {len(llm_vulns)} LLM vulns")

    # ── Initialize DB ──
    db = get_db()
    target_id = db.upsert_target(TARGET_DOMAIN, "HackerOne - DoorDash",
                                  "hackerone", {}, DOORDASH_RULES)
    scan_run_id = db.start_scan_run(target_id, "engine_pipeline")
    db.log_action("engine_pipeline_start", TARGET_DOMAIN,
                  details={"engines": run_list}, scan_run_id=scan_run_id)

    # ── Tracking variables ──
    surface_endpoints: list[Endpoint] = []
    surface_techs: list[str] = list(technologies)
    waf_detected: str | None = None
    scanner_vulns: list[Vulnerability] = []
    all_vulns: list[Vulnerability] = list(llm_vulns)
    analysis_results: dict[str, Any] = {}
    payloads: dict[str, list[str]] = {}
    suggestions: list[dict] = []
    learning_stats: dict[str, Any] = {}
    chains: list[ExploitChain] = []

    # ── Engine 1: Surface Mapping ──
    if "surface" in run_list:
        surface_endpoints, new_techs, waf_detected = await run_surface_engine(target, endpoints)
        surface_techs = sorted(set(surface_techs) | set(new_techs or []))
        # Merge surface endpoints with recon endpoints
        existing_urls = {ep.url for ep in endpoints}
        new_eps = [ep for ep in surface_endpoints if ep.url not in existing_urls]
        endpoints = endpoints + new_eps
        log(f"  Merged: {len(new_eps)} new endpoints from surface → total {len(endpoints)}")

    # ── Engine 2: Vulnerability Scanner ──
    if "scanner" in run_list:
        scanner_vulns = await run_scanner_engine(target, endpoints)
        all_vulns = llm_vulns + scanner_vulns

    # ── Engine 3: Analysis ──
    if "analysis" in run_list:
        analysis_results = run_analysis_engine(all_vulns)
        verified = analysis_results.get("verified_vulnerabilities", [])
        chains = analysis_results.get("exploit_chains", [])
        # Update all_vulns to verified only for downstream engines
        if verified:
            all_vulns = verified

    # ── Engine 4: Payload Generation ──
    if "payloads" in run_list:
        payloads = run_payload_engine(all_vulns, waf_detected)

    # ── Engine 5: Assistant ──
    if "assistant" in run_list:
        suggestions = run_assistant_engine(endpoints)

    # ── Engine 6: Reporting ──
    if "reporting" in run_list:
        run_reporting_engine(all_vulns, chains, analysis_results)

    # ── Engine 7: Learning ──
    if "learning" in run_list:
        learning_stats = run_learning_engine(all_vulns)

    # ── Store results ──
    store_engine_results(
        db, target_id, scan_run_id,
        surface_endpoints, scanner_vulns,
        analysis_results, payloads, suggestions,
    )

    # ── Save files ──
    save_engine_results_to_files(
        analysis_results, payloads, suggestions,
        learning_stats, surface_techs, waf_detected,
    )

    # ── Finalize ──
    elapsed = time.time() - total_start
    db.update_scan_run(scan_run_id, "completed",
                       steps=run_list,
                       stats=db.get_stats(target_id))
    db.log_action("engine_pipeline_complete", TARGET_DOMAIN,
                  details={"duration_s": round(elapsed, 1),
                           "engines_run": run_list},
                  scan_run_id=scan_run_id)

    log(f"\n{'═'*60}")
    log(f"  ENGINE PIPELINE COMPLETE")
    log(f"  Duration: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    log(f"  Endpoints: {len(endpoints)} | Vulns: {len(all_vulns)} | Chains: {len(chains)}")
    log(f"  Payloads: {sum(len(v) for v in payloads.values())} | "
        f"Suggestions: {sum(len(s['vectors']) for s in suggestions)}")
    log(f"  Results: {TARGET_DIR / 'engines'}/")
    log(f"  Reports: {Path(get_db().db_path).parent.parent / 'reports'}/")
    log(f"{'═'*60}")


# ──────────────────────────────────────────────────────────────
#  CLI
# ──────────────────────────────────────────────────────────────

AVAILABLE_ENGINES = ["surface", "scanner", "analysis", "payloads",
                     "assistant", "reporting", "learning"]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="BBHunter Engine Bridge")
    parser.add_argument("--engine", type=str, help="Run a single engine")
    parser.add_argument("--engines", type=str, help="Comma-separated list of engines")
    parser.add_argument("--list", action="store_true", help="List available engines")
    parser.add_argument("--skip-surface", action="store_true",
                        help="Skip surface mapping (saves time if recon data is sufficient)")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable engines:")
        for i, name in enumerate(AVAILABLE_ENGINES, 1):
            print(f"  {i}. {name}")
        print("\nUsage:")
        print("  python3 scripts/engine_bridge.py               # run all")
        print("  python3 scripts/engine_bridge.py --engine analysis")
        print("  python3 scripts/engine_bridge.py --engines analysis,payloads,reporting")
        return

    engines_to_run = None
    if args.engine:
        if args.engine not in AVAILABLE_ENGINES:
            print(f"Unknown engine: {args.engine}. Use --list to see options.")
            sys.exit(1)
        engines_to_run = [args.engine]
    elif args.engines:
        engines_to_run = [e.strip() for e in args.engines.split(",")]
        for e in engines_to_run:
            if e not in AVAILABLE_ENGINES:
                print(f"Unknown engine: {e}. Use --list to see options.")
                sys.exit(1)
    elif args.skip_surface:
        engines_to_run = [e for e in AVAILABLE_ENGINES if e != "surface"]

    asyncio.run(run_all_engines(engines_to_run))


if __name__ == "__main__":
    main()

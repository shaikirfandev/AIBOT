#!/usr/bin/env python3
"""
BBHunter - Automated Passive Recon Pipeline
============================================
Runs passive recon tools ONE BY ONE against the target.
Each step produces a data file in data/<target>/.
NO active scanning - DoorDash prohibits automated scanners.

Usage:
    python3 scripts/hunt.py                      # run all steps
    python3 scripts/hunt.py --step subdomain_enum # run single step
    python3 scripts/hunt.py --list                # list steps
"""

import subprocess
import sys
import time
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich import box

console = Console()

# Add parent to path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (
    TARGET_DOMAIN, TARGET_DIR, TOOLS, DOORDASH_RULES,
    LOGS_DIR, ensure_dirs, GO_BIN, TARGET_LLM_DIR,
    LLM_MODEL, STEP_TIMEOUT, MAX_CONSECUTIVE_FAILURES,
    PROGRAM_NAME,
)
from db_manager import (
    get_db, DBManager, SafetyChecker, parse_llm_findings,
)

# LLM integration flag (set False with --no-llm)
LLM_ENABLED = True

# Step timeout (seconds) — 0 means no limit
_step_timeout: int = STEP_TIMEOUT


class StepTimeoutError(Exception):
    """Raised when a recon step exceeds its allowed timeout."""
    pass


def _timeout_handler(signum, frame):
    raise StepTimeoutError("Step exceeded timeout limit")


def run_step_with_timeout(name: str, func, timeout: int = 0) -> str:
    """
    Run a recon step function with an optional timeout.
    Returns '✓' on success, '⏭' on timeout/skip, '✗' on error.
    """
    import signal
    effective_timeout = timeout or _step_timeout
    old_handler = None

    try:
        if effective_timeout > 0:
            old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(effective_timeout)

        func()

        if effective_timeout > 0:
            signal.alarm(0)  # cancel alarm
        return "✓"

    except StepTimeoutError:
        log(f"⏭ Step '{name}' skipped: exceeded {effective_timeout}s timeout", "WARN")
        db_log("step_timeout", name,
               details={"timeout_s": effective_timeout}, level="WARN")
        return "⏭"

    except Exception as e:
        if effective_timeout > 0:
            signal.alarm(0)
        log(f"Step {name} failed: {e}", "ERROR")
        db_log("step_error", name, details={"error": str(e)}, level="ERROR")
        return "✗"

    finally:
        if effective_timeout > 0:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)

# ── Database + Safety (initialized in main) ──────────────────
_db: DBManager = None
_target_id: str = ""
_scan_id: str = ""
_safety: SafetyChecker = None


def init_db_and_safety():
    """Initialize DB, register target, start scan run, init safety gate."""
    global _db, _target_id, _scan_id, _safety
    _db = get_db()
    _target_id = _db.upsert_target(
        domain=TARGET_DOMAIN,
        program=PROGRAM_NAME,
        platform="hackerone",
        scope={"in_scope": DOORDASH_RULES.get("in_scope", [])},
        rules=DOORDASH_RULES,
    )
    _scan_id = _db.start_scan(_target_id, "passive_recon")
    _safety = SafetyChecker(DOORDASH_RULES)
    _db.log_action("pipeline_start", TARGET_DOMAIN,
                   details={"scan_id": _scan_id},
                   scan_id=_scan_id)
    log(f"🗄️  DB initialized: {_db.db_path}")
    log(f"🔒 Safety gate active (scope enforcement)")
    log(f"📋 Scan run: {_scan_id[:8]}...")


# ─────────────────────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────────────────────

def log(msg: str, level: str = "INFO"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    log_file = LOGS_DIR / "hunt.log"
    with open(log_file, "a") as f:
        f.write(line + "\n")


def db_log(action: str, step_name: str = "", tool_name: str = "",
           details: dict = None, level: str = "INFO"):
    """Log action to DB audit trail (safe if DB not yet initialized)."""
    if _db:
        try:
            _db.log_action(action, TARGET_DOMAIN, step_name, tool_name,
                           details or {}, level, _scan_id)
        except Exception as exc:
            log(f"db_log failed: {exc}", "DEBUG")


def run_tool(cmd: list[str], outfile: Path, timeout: int = 600) -> bool:
    """Run a command, capture stdout to outfile. Returns True on success."""
    tool_name = str(cmd[0]).split("/")[-1] if cmd else "unknown"
    log(f"Running: {' '.join(str(c) for c in cmd)}")
    log(f"Output → {outfile}")
    db_log("tool_start", tool_name=tool_name,
           details={"cmd": " ".join(str(c) for c in cmd[:5]), "outfile": str(outfile)})
    try:
        env = dict(
            HOME=str(Path.home()),
            PATH=f"{GO_BIN}:/usr/local/bin:/usr/bin:/bin:{Path.home()}/.local/bin",
            GOPATH=str(Path.home() / "go"),
        )
        result = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True, text=True,
            timeout=timeout, env=env,
        )
        # Combine stdout (some tools use stderr for output)
        output = result.stdout
        if not output.strip() and result.stderr.strip():
            output = result.stderr

        with open(outfile, "w") as f:
            f.write(output)

        lines = len(output.strip().splitlines()) if output.strip() else 0
        log(f"✓ Completed: {lines} lines captured")
        return True

    except subprocess.TimeoutExpired:
        log(f"✗ Timeout after {timeout}s", "WARN")
        return False
    except FileNotFoundError as e:
        log(f"✗ Tool not found: {e}", "ERROR")
        return False
    except Exception as e:
        log(f"✗ Error: {e}", "ERROR")
        return False


def run_pipe(cmd1: list[str], cmd2: list[str], outfile: Path, timeout: int = 600) -> bool:
    """Run cmd1 | cmd2, save output to outfile."""
    log(f"Running: {' '.join(str(c) for c in cmd1)} | {' '.join(str(c) for c in cmd2)}")
    try:
        env = dict(
            HOME=str(Path.home()),
            PATH=f"{GO_BIN}:/usr/local/bin:/usr/bin:/bin:{Path.home()}/.local/bin",
            GOPATH=str(Path.home() / "go"),
        )
        p1 = subprocess.Popen(
            [str(c) for c in cmd1],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )
        p2 = subprocess.Popen(
            [str(c) for c in cmd2],
            stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env,
        )
        p1.stdout.close()
        out, err = p2.communicate(timeout=timeout)
        output = out.decode(errors="replace")
        if not output.strip():
            output = err.decode(errors="replace")

        with open(outfile, "w") as f:
            f.write(output)

        lines = len(output.strip().splitlines()) if output.strip() else 0
        log(f"✓ Completed: {lines} lines captured")
        return True
    except Exception as e:
        log(f"✗ Pipeline error: {e}", "ERROR")
        return False


def filter_in_scope(lines: list[str]) -> list[str]:
    """Remove out-of-scope domains using SafetyChecker + fallback rules."""
    filtered = []
    blocked = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Use SafetyChecker if available
        if _safety:
            if _safety.is_in_scope(line):
                filtered.append(line)
            else:
                blocked += 1
            continue

        # Fallback: manual check
        oos_domains = set(DOORDASH_RULES["out_of_scope_domains"])
        oos_wildcards = DOORDASH_RULES["out_of_scope_wildcards"]

        domain = line
        if "://" in line:
            domain = line.split("://", 1)[1].split("/")[0].split(":")[0]

        if domain in oos_domains:
            blocked += 1
            continue

        skip = False
        for wc in oos_wildcards:
            pattern = wc.replace("*.", "")
            if domain.endswith(pattern):
                skip = True
                break
        if skip:
            blocked += 1
            continue

        if any(line.count(p.replace("*", "")) > 0 for p in DOORDASH_RULES.get("out_of_scope_paths", [])):
            blocked += 1
            continue

        filtered.append(line)

    if blocked:
        db_log("scope_filter", details={"blocked": blocked, "passed": len(filtered)})
    return filtered


# ─────────────────────────────────────────────────────────────
#  LLM Chunk Analysis (wired into each step)
# ─────────────────────────────────────────────────────────────

def analyze_step_output(step_name: str, output_files: list[Path]):
    """
    After a recon step completes, chunk its output files and send
    each chunk to the local LLM for security analysis.
    Results are saved in llm_analysis/<target>/<step_name>/.
    """
    if not LLM_ENABLED:
        return

    try:
        from llm_analyzer import (
            query_llm, chunk_text, check_llm_health,
            get_analysis_prompt, SYSTEM_PROMPT,
        )
    except ImportError as e:
        log(f"LLM analyzer not available: {e}", "WARN")
        return

    # Quick health check (don't block recon if LLM is down)
    if not check_llm_health():
        log("LLM not available, skipping analysis for this step", "WARN")
        return

    for filepath in output_files:
        if not filepath.exists() or filepath.stat().st_size == 0:
            continue

        filename = filepath.name
        content = filepath.read_text()
        if not content.strip():
            continue

        chunks = chunk_text(content)
        if not chunks:
            continue

        # Output directory for this file's analysis
        file_output_dir = TARGET_LLM_DIR / filename.replace(".txt", "")
        file_output_dir.mkdir(parents=True, exist_ok=True)

        log(f"🤖 LLM analyzing {filename}: {len(chunks)} chunks")
        db_log("llm_analysis_start", step_name, details={
            "file": filename, "chunks": len(chunks)})

        total_tokens = 0
        total_duration = 0.0
        consecutive_llm_failures = 0

        for chunk in chunks:
            chunk_file = file_output_dir / f"chunk_{chunk['index']:03d}.json"
            if chunk_file.exists():
                consecutive_llm_failures = 0
                continue  # Skip already processed

            # Skip remaining chunks after too many consecutive failures
            if MAX_CONSECUTIVE_FAILURES > 0 and consecutive_llm_failures >= MAX_CONSECUTIVE_FAILURES:
                remaining = len(chunks) - chunk["index"]
                log(f"   ⚠️  {consecutive_llm_failures} consecutive LLM failures — "
                    f"skipping remaining {remaining} chunks", "WARN")
                break

            log(f"   Chunk {chunk['index']+1}/{len(chunks)} "
                f"({chunk['char_count']} chars)...")

            prompt = get_analysis_prompt(
                filename, chunk["index"], len(chunks), chunk["text"]
            )
            result = query_llm(prompt, SYSTEM_PROMPT)

            import json as _json
            chunk_result = {
                "chunk_index": chunk["index"],
                "chunk_hash": chunk["hash"],
                "llm_response": result.get("response", ""),
                "tokens_eval": result.get("tokens_eval", 0),
                "duration_s": result.get("duration_s", 0),
                "success": result.get("success", False),
            }
            chunk_file.write_text(_json.dumps(chunk_result, indent=2))

            # ── Store LLM chunk in DB ──
            if _db:
                _db.store_llm_chunk(_target_id, _scan_id, {
                    "source_file": filename,
                    "chunk_index": chunk["index"],
                    "total_chunks": len(chunks),
                    "chunk_hash": chunk["hash"],
                    "chunk_chars": chunk["char_count"],
                    "chunk_lines": chunk["line_count"],
                    "prompt_text": prompt[:500],  # truncate for DB
                    "response_text": result.get("response", ""),
                    "tokens_prompt": result.get("tokens_prompt", 0),
                    "tokens_eval": result.get("tokens_eval", 0),
                    "duration_s": result.get("duration_s", 0),
                    "success": result.get("success", False),
                    "error": result.get("error", ""),
                    "llm_model": LLM_MODEL,
                })

            if result["success"]:
                total_tokens += result.get("tokens_eval", 0)
                total_duration += result.get("duration_s", 0)
                consecutive_llm_failures = 0
                log(f" ✓ ({result['duration_s']}s)")

                # ── Parse & store findings from this chunk ──
                if _db and result.get("response"):
                    findings = parse_llm_findings(result["response"])
                    if findings:
                        for f in findings:
                            f["source"] = f"llm_{step_name}"
                        _db.store_vulnerabilities(_target_id, _scan_id, findings)
                        log(f"   💾 {len(findings)} finding(s) → DB")
            else:
                consecutive_llm_failures += 1
                log(f" ✗ {result.get('error', 'no response')}"
                    f" (failures: {consecutive_llm_failures}/{MAX_CONSECUTIVE_FAILURES})")

            time.sleep(1)  # Brief pause between chunks

        # Merge analyses into one readable file
        merge_file = file_output_dir / "_merged_analysis.txt"
        import json as _json
        merged = [f"LLM Analysis: {filename}\n{'='*50}"]
        for cf in sorted(file_output_dir.glob("chunk_*.json")):
            try:
                d = _json.loads(cf.read_text())
                if d.get("success") and d.get("llm_response"):
                    merged.append(f"\n--- Chunk {d['chunk_index']+1} ---")
                    merged.append(d["llm_response"])
            except Exception as exc:
                log(f"Failed to parse chunk data for merging: {exc}", "DEBUG")
        merged_text = "\n".join(merged) + "\n"
        merge_file.write_text(merged_text)

        # ── Store merged analysis in DB ──
        if _db:
            _db.store_llm_analysis(_target_id, _scan_id, {
                "source_file": filename,
                "merged_text": merged_text,
                "chunks_total": len(chunks),
                "chunks_done": len(chunks),
                "total_tokens": total_tokens,
                "total_duration_s": total_duration,
            })

        db_log("llm_analysis_complete", step_name, details={
            "file": filename, "chunks": len(chunks),
            "tokens": total_tokens, "duration_s": round(total_duration, 1)})
        log(f"✅ LLM analysis saved → {file_output_dir.name}/ + DB")


# ─────────────────────────────────────────────────────────────
#  Recon Steps (each is a function)
# ─────────────────────────────────────────────────────────────

def step_subdomain_enum():
    """Step 1: Passive subdomain enumeration with subfinder."""
    log("═══ STEP 1: Subdomain Enumeration (subfinder) ═══")
    db_log("step_start", "subdomain_enum", "subfinder")
    outfile = TARGET_DIR / "01_subdomains_raw.txt"

    # Check if we already have data from previous run
    existing = TARGET_DIR / "subdomains_subfinder.txt"
    if existing.exists() and existing.stat().st_size > 0:
        log("Found existing subfinder data, copying...")
        shutil.copy2(existing, outfile)
    else:
        run_tool(
            [TOOLS["subfinder"], "-d", TARGET_DOMAIN, "-silent", "-all"],
            outfile, timeout=300,
        )

    # Filter out-of-scope
    if outfile.exists():
        lines = outfile.read_text().strip().splitlines()
        filtered = filter_in_scope(lines)
        inscope_file = TARGET_DIR / "01_subdomains_inscope.txt"
        inscope_file.write_text("\n".join(sorted(set(filtered))) + "\n")
        log(f"Subdomains: {len(lines)} total → {len(filtered)} in-scope")

        # Also save out-of-scope for awareness
        oos = set(lines) - set(filtered)
        oos_file = TARGET_DIR / "01_subdomains_outofscope.txt"
        oos_file.write_text("\n".join(sorted(oos)) + "\n")
        log(f"Out-of-scope subdomains logged: {len(oos)}")

        # ── Store subdomains in DB ──
        if _db:
            assets = []
            for sub in sorted(set(filtered)):
                assets.append({"type": "subdomain", "value": sub.strip(),
                               "source": "subfinder", "in_scope": 1})
            for sub in sorted(oos):
                assets.append({"type": "subdomain", "value": sub.strip(),
                               "source": "subfinder", "in_scope": 0})
            inserted = _db.store_assets(_target_id, _scan_id, assets)
            log(f"💾 {inserted} subdomains → DB")

    db_log("step_complete", "subdomain_enum", details={"total": len(lines) if outfile.exists() else 0})
    analyze_step_output("subdomain_enum", [
        TARGET_DIR / "01_subdomains_inscope.txt",
    ])
    return True


def step_amass_enum():
    """Step 1b: Subdomain enrichment with amass (passive mode)."""
    log("═══ STEP 1b: Subdomain Enrichment (amass passive) ═══")
    db_log("step_start", "amass_enum", "amass")
    outfile = TARGET_DIR / "01b_subdomains_amass.txt"

    amass_path = TOOLS.get("amass")
    if not amass_path or not amass_path.exists():
        log("amass not found, skipping", "WARN")
        return False

    run_tool(
        [amass_path, "enum", "-passive", "-d", TARGET_DOMAIN, "-silent"],
        outfile, timeout=600,
    )

    if outfile.exists() and outfile.stat().st_size > 0:
        amass_subs = set(outfile.read_text().strip().splitlines())
        amass_filtered = filter_in_scope(list(amass_subs))
        log(f"Amass found {len(amass_subs)} subs → {len(amass_filtered)} in-scope")

        # Merge with subfinder results
        merged_file = TARGET_DIR / "01_subdomains_inscope.txt"
        existing = set()
        if merged_file.exists():
            existing = set(merged_file.read_text().strip().splitlines())
        new_subs = set(amass_filtered) - existing
        all_subs = sorted(existing | set(amass_filtered))
        merged_file.write_text("\n".join(all_subs) + "\n")
        log(f"Merged: {len(existing)} existing + {len(new_subs)} new = {len(all_subs)} total")

        # Store new amass subdomains in DB
        if _db and new_subs:
            assets = [{"type": "subdomain", "value": s.strip(),
                       "source": "amass", "in_scope": 1} for s in sorted(new_subs)]
            inserted = _db.store_assets(_target_id, _scan_id, assets)
            log(f"💾 {inserted} new amass subdomains → DB")

    db_log("step_complete", "amass_enum")
    analyze_step_output("amass_enum", [outfile])
    return True


def step_dns_resolution():
    """Step 2: DNS resolution of discovered subdomains."""
    log("═══ STEP 2: DNS Resolution (dnsx + dig) ═══")
    db_log("step_start", "dns_resolution", "dnsx")

    subs_file = TARGET_DIR / "01_subdomains_inscope.txt"
    if not subs_file.exists():
        log("No subdomains file found, skipping DNS step", "WARN")
        return False

    outfile = TARGET_DIR / "02_dns_resolved.txt"

    # Use dnsx if available
    dnsx_path = TOOLS.get("dnsx")
    if dnsx_path and dnsx_path.exists():
        run_tool(
            [dnsx_path, "-l", str(subs_file), "-silent", "-a", "-aaaa", "-cname", "-resp"],
            outfile, timeout=300,
        )
    else:
        # Fallback: dig each subdomain
        log("dnsx not found, using dig fallback (slower)")
        subs = subs_file.read_text().strip().splitlines()
        results = []
        for sub in subs[:100]:  # limit to first 100 to avoid long runtime
            try:
                res = subprocess.run(
                    ["dig", "+short", sub.strip()],
                    capture_output=True, text=True, timeout=10,
                )
                if res.stdout.strip():
                    results.append(f"{sub.strip()} [{res.stdout.strip().replace(chr(10), ', ')}]")
            except Exception as exc:
                log(f"DNS resolution failed for {sub.strip()}: {exc}", "DEBUG")
        outfile.write_text("\n".join(results) + "\n")
        log(f"Resolved {len(results)} subdomains via dig")

    # ── Store DNS records in DB ──
    if _db and outfile.exists():
        records = []
        for line in outfile.read_text().strip().splitlines():
            line = line.strip()
            if not line:
                continue
            # dnsx format: subdomain [A] [IP] or subdomain [CNAME] [target]
            parts = line.split()
            subdomain = parts[0] if parts else line
            records.append({"subdomain": subdomain, "raw_line": line})
        inserted = _db.store_dns_records(_target_id, _scan_id, records)
        log(f"💾 {inserted} DNS records → DB")

    db_log("step_complete", "dns_resolution")
    analyze_step_output("dns_resolution", [TARGET_DIR / "02_dns_resolved.txt"])
    return True


def step_httpx_probe():
    """Step 2b: Probe live hosts with httpx (passive, no fuzzing)."""
    log("═══ STEP 2b: Live Host Probing (httpx) ═══")
    db_log("step_start", "httpx_probe", "httpx")

    httpx_path = TOOLS.get("httpx")
    if not httpx_path or not httpx_path.exists():
        log("httpx not found, skipping", "WARN")
        return False

    subs_file = TARGET_DIR / "01_subdomains_inscope.txt"
    if not subs_file.exists():
        log("No subdomains file found, skipping httpx", "WARN")
        return False

    outfile = TARGET_DIR / "02b_httpx_live.txt"

    # httpx flags: status code, title, tech, content-length, web-server, no active scan
    run_tool(
        [httpx_path, "-l", str(subs_file), "-silent",
         "-status-code", "-title", "-tech-detect",
         "-content-length", "-web-server",
         "-threads", "5",
         "-rate-limit", "10",
         "-H", DOORDASH_RULES["required_header"]],
        outfile, timeout=600,
    )

    if outfile.exists() and outfile.stat().st_size > 0:
        lines = outfile.read_text().strip().splitlines()
        log(f"httpx: {len(lines)} live hosts detected")

        # Store as assets + technologies in DB
        if _db:
            assets = []
            techs = []
            for line in lines:
                parts = line.split()
                url = parts[0] if parts else line
                assets.append({"type": "live_host", "value": url.strip(),
                               "source": "httpx", "in_scope": 1})
                # Parse httpx output for tech info
                if len(parts) > 1:
                    techs.append({
                        "url": url.strip(),
                        "tech_name": "httpx_fingerprint",
                        "header_value": " ".join(parts[1:])[:300],
                    })
            inserted_a = _db.store_assets(_target_id, _scan_id, assets)
            inserted_t = _db.store_technologies(_target_id, _scan_id, techs)
            log(f"💾 {inserted_a} live hosts + {inserted_t} tech entries → DB")

    db_log("step_complete", "httpx_probe")
    analyze_step_output("httpx_probe", [outfile])
    return True


def step_url_discovery():
    """Step 3: Passive URL discovery with gau."""
    log("═══ STEP 3: URL Discovery (gau - passive) ═══")
    db_log("step_start", "url_discovery", "gau")
    outfile = TARGET_DIR / "03_urls_gau_raw.txt"

    # Check existing
    existing = TARGET_DIR / "urls_gau.txt"
    if existing.exists() and existing.stat().st_size > 0:
        log("Found existing gau data, copying...")
        shutil.copy2(existing, outfile)
    else:
        # gau reads domain from stdin
        run_pipe(
            ["echo", TARGET_DOMAIN],
            [TOOLS["gau"], "--threads", "3", "--subs"],
            outfile, timeout=600,
        )

    # Filter and deduplicate
    if outfile.exists():
        lines = outfile.read_text().strip().splitlines()
        filtered = filter_in_scope(lines)
        unique = sorted(set(filtered))

        clean_file = TARGET_DIR / "03_urls_clean.txt"
        clean_file.write_text("\n".join(unique) + "\n")
        log(f"URLs: {len(lines)} raw → {len(unique)} unique in-scope")

        # Extract interesting URL patterns
        interesting = []
        patterns = [
            r'api[/.]', r'graphql', r'\.json', r'\.xml', r'\.yaml',
            r'admin', r'dashboard', r'login', r'auth', r'token',
            r'upload', r'file', r'download', r'export', r'import',
            r'redirect', r'callback', r'webhook', r'\.env',
            r'config', r'debug', r'test', r'staging', r'dev',
            r'password', r'reset', r'forgot', r'register', r'signup',
            r'payment', r'checkout', r'order', r'cart', r'invoice',
            r'\.js$', r'\.map$', r'swagger', r'openapi', r'docs/api',
            r'internal', r'private', r'secret', r'backup',
            r'\?.*=', r'&.*=',  # URLs with parameters
        ]
        for url in unique:
            for pat in patterns:
                if re.search(pat, url, re.IGNORECASE):
                    interesting.append(url)
                    break

        int_file = TARGET_DIR / "03_urls_interesting.txt"
        int_file.write_text("\n".join(sorted(set(interesting))) + "\n")
        log(f"Interesting URLs flagged: {len(set(interesting))}")

        # ── Store endpoints in DB ──
        if _db:
            eps = []
            interesting_set = set(interesting)
            for url in unique:
                eps.append({
                    "url": url, "source": "gau",
                    "is_interesting": 1 if url in interesting_set else 0,
                    "category": "url_discovery",
                })
            inserted = _db.store_endpoints(_target_id, _scan_id, eps)
            log(f"💾 {inserted} endpoints → DB")

    db_log("step_complete", "url_discovery")

    analyze_step_output("url_discovery", [
        TARGET_DIR / "03_urls_interesting.txt",  # Analyze interesting URLs only (not all 4500+)
    ])
    return True


def step_wayback_urls():
    """Step 4: Additional URL discovery from Wayback Machine."""
    log("═══ STEP 4: Wayback Machine URLs ═══")
    db_log("step_start", "wayback_urls", "waybackurls")
    outfile = TARGET_DIR / "04_wayback_urls.txt"

    run_pipe(
        ["echo", f"www.{TARGET_DOMAIN}"],
        [TOOLS["waybackurls"]],
        outfile, timeout=300,
    )

    if outfile.exists():
        lines = outfile.read_text().strip().splitlines()
        filtered = filter_in_scope(lines)
        unique = sorted(set(filtered))

        clean_file = TARGET_DIR / "04_wayback_clean.txt"
        clean_file.write_text("\n".join(unique) + "\n")
        log(f"Wayback URLs: {len(lines)} raw → {len(unique)} unique in-scope")

        # Extract parameters from wayback URLs
        params = set()
        for url in unique:
            if "?" in url:
                query = url.split("?", 1)[1]
                for pair in query.split("&"):
                    if "=" in pair:
                        param_name = pair.split("=", 1)[0]
                        params.add(param_name)

        if params:
            param_file = TARGET_DIR / "04_wayback_params.txt"
            param_file.write_text("\n".join(sorted(params)) + "\n")
            log(f"Unique parameters discovered: {len(params)}")

        # ── Store wayback URLs in DB ──
        if _db:
            eps = [{"url": u, "source": "waybackurls", "category": "wayback"}
                   for u in unique]
            inserted = _db.store_endpoints(_target_id, _scan_id, eps)
            log(f"💾 {inserted} wayback endpoints → DB")

    db_log("step_complete", "wayback_urls")

    # Feed wayback data to LLM
    analyze_step_output("wayback_urls", [
        TARGET_DIR / "04_wayback_clean.txt",
        TARGET_DIR / "04_wayback_params.txt",
    ])
    return True


def step_katana_crawl():
    """Step 4b: Passive web crawling with katana."""
    log("═══ STEP 4b: Web Crawling (katana passive) ═══")
    db_log("step_start", "katana_crawl", "katana")

    katana_path = TOOLS.get("katana")
    if not katana_path or not katana_path.exists():
        log("katana not found, skipping", "WARN")
        return False

    outfile = TARGET_DIR / "04b_katana_urls.txt"

    # katana in passive mode: crawl known endpoints, extract URLs/forms
    # -passive flag uses wayback/commoncrawl/alienvault sources
    run_tool(
        [katana_path, "-u", f"https://www.{TARGET_DOMAIN}",
         "-passive", "-silent",
         "-depth", "3",
         "-jc",              # extract from JS
         "-kf", "all",       # known file extensions
         "-rate-limit", "5",
         "-H", DOORDASH_RULES["required_header"]],
        outfile, timeout=600,
    )

    if outfile.exists() and outfile.stat().st_size > 0:
        lines = outfile.read_text().strip().splitlines()
        filtered = filter_in_scope(lines)
        unique = sorted(set(filtered))

        clean_file = TARGET_DIR / "04b_katana_clean.txt"
        clean_file.write_text("\n".join(unique) + "\n")
        log(f"Katana: {len(lines)} raw → {len(unique)} unique in-scope URLs")

        # Extract interesting patterns
        interesting = []
        for url in unique:
            if re.search(r'api[/.]|graphql|\.json|\.xml|admin|dashboard|login|auth|config|\.env|swagger|debug|internal',
                         url, re.IGNORECASE):
                interesting.append(url)

        if interesting:
            int_file = TARGET_DIR / "04b_katana_interesting.txt"
            int_file.write_text("\n".join(sorted(set(interesting))) + "\n")
            log(f"Katana interesting URLs: {len(set(interesting))}")

        # Store in DB
        if _db:
            eps = [{"url": u, "source": "katana",
                    "is_interesting": 1 if u in set(interesting) else 0,
                    "category": "katana_crawl"} for u in unique]
            inserted = _db.store_endpoints(_target_id, _scan_id, eps)
            log(f"💾 {inserted} katana endpoints → DB")

    db_log("step_complete", "katana_crawl")
    analyze_step_output("katana_crawl", [
        TARGET_DIR / "04b_katana_clean.txt",
    ])
    return True


def step_hakrawler():
    """Step 4c: Link extraction with hakrawler (passive)."""
    log("═══ STEP 4c: Link Extraction (hakrawler) ═══")
    db_log("step_start", "hakrawler", "hakrawler")

    hakrawler_path = TOOLS.get("hakrawler")
    if not hakrawler_path or not hakrawler_path.exists():
        log("hakrawler not found, skipping", "WARN")
        return False

    outfile = TARGET_DIR / "04c_hakrawler_urls.txt"

    # hakrawler reads URLs from stdin, extracts links/forms/js refs
    # Feed it the main target URL
    run_pipe(
        ["echo", f"https://www.{TARGET_DOMAIN}"],
        [hakrawler_path, "-d", "3", "-t", "5", "-plain"],
        outfile, timeout=300,
    )

    if outfile.exists() and outfile.stat().st_size > 0:
        lines = outfile.read_text().strip().splitlines()
        filtered = filter_in_scope(lines)
        unique = sorted(set(filtered))

        clean_file = TARGET_DIR / "04c_hakrawler_clean.txt"
        clean_file.write_text("\n".join(unique) + "\n")
        log(f"Hakrawler: {len(lines)} raw → {len(unique)} unique in-scope")

        # Categorize extracted links
        forms = [u for u in unique if re.search(r'form|action=|method=', u, re.IGNORECASE)]
        js_refs = [u for u in unique if re.search(r'\.js(\?|$)', u, re.IGNORECASE)]
        api_refs = [u for u in unique if re.search(r'api[/.]|graphql|/v\d+/', u, re.IGNORECASE)]

        if forms or js_refs or api_refs:
            cat_file = TARGET_DIR / "04c_hakrawler_categorized.txt"
            cat_lines = [f"Hakrawler Categorized Results for {TARGET_DOMAIN}", "="*60]
            if forms:
                cat_lines.append(f"\n[FORMS] ({len(forms)})")
                cat_lines.extend([f"  {u}" for u in forms[:50]])
            if js_refs:
                cat_lines.append(f"\n[JS FILES] ({len(js_refs)})")
                cat_lines.extend([f"  {u}" for u in js_refs[:50]])
            if api_refs:
                cat_lines.append(f"\n[API ENDPOINTS] ({len(api_refs)})")
                cat_lines.extend([f"  {u}" for u in api_refs[:50]])
            cat_file.write_text("\n".join(cat_lines) + "\n")

        # Store in DB
        if _db:
            eps = [{"url": u, "source": "hakrawler",
                    "is_interesting": 1 if u in set(forms + js_refs + api_refs) else 0,
                    "category": "hakrawler"} for u in unique]
            inserted = _db.store_endpoints(_target_id, _scan_id, eps)
            log(f"💾 {inserted} hakrawler endpoints → DB")

    db_log("step_complete", "hakrawler")
    analyze_step_output("hakrawler", [
        TARGET_DIR / "04c_hakrawler_clean.txt",
    ])
    return True


def step_tech_detection():
    """Step 5: Technology detection via HTTP headers (passive)."""
    log("═══ STEP 5: Technology Detection (curl headers) ═══")
    db_log("step_start", "tech_detection", "curl")

    targets = [f"https://www.{TARGET_DOMAIN}", f"https://{TARGET_DOMAIN}"]

    # Read some subdomains for header analysis
    subs_file = TARGET_DIR / "01_subdomains_inscope.txt"
    if subs_file.exists():
        subs = subs_file.read_text().strip().splitlines()[:20]
        targets.extend([f"https://{s.strip()}" for s in subs if s.strip()])

    results = []
    for target in targets:
        try:
            res = subprocess.run(
                ["curl", "-sI", "-m", "10",
                 "-H", DOORDASH_RULES["required_header"],
                 "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                 target],
                capture_output=True, text=True, timeout=15,
            )
            if res.stdout.strip():
                results.append(f"\n{'='*60}\nTARGET: {target}\n{'='*60}")
                results.append(res.stdout.strip())
        except Exception as e:
            results.append(f"[ERROR] {target}: {e}")

        time.sleep(0.5)  # Rate limiting: 2 req/s max

    outfile = TARGET_DIR / "05_tech_headers.txt"
    outfile.write_text("\n".join(results) + "\n")
    log(f"Scanned {len(targets)} targets for headers/tech")

    # ── Store technology data in DB ──
    if _db:
        techs = []
        current_url = ""
        current_headers = ""
        for line in results:
            if line.startswith("TARGET:"):
                if current_url and current_headers:
                    techs.append({"url": current_url, "raw_headers": current_headers})
                current_url = line.replace("TARGET:", "").strip()
                current_headers = ""
            else:
                current_headers += line + "\n"
                # Extract specific headers
                ll = line.lower().strip()
                for hname in ["server", "x-powered-by", "x-frame-options",
                              "content-security-policy", "strict-transport-security"]:
                    if ll.startswith(hname + ":"):
                        techs.append({
                            "url": current_url, "header_name": hname,
                            "header_value": line.split(":", 1)[1].strip()[:200],
                            "tech_name": hname,
                        })
        if current_url and current_headers:
            techs.append({"url": current_url, "raw_headers": current_headers})
        inserted = _db.store_technologies(_target_id, _scan_id, techs)
        log(f"💾 {inserted} tech entries → DB")

    db_log("step_complete", "tech_detection")

    # Feed tech headers to LLM
    analyze_step_output("tech_detection", [outfile])
    return True


def step_port_scan_passive():
    """Step 6: Passive port/service info from Shodan/Censys (via headers only)."""
    log("═══ STEP 6: Service Fingerprinting (passive) ═══")
    db_log("step_start", "port_scan_passive", "curl")

    # We do NOT actively port scan (DoorDash rules)
    # Instead, extract service info from headers + known ports
    outfile = TARGET_DIR / "06_services_passive.txt"

    # Check common web ports on main domain only via curl
    common_ports = [80, 443, 8080, 8443]
    results = []

    for port in common_ports:
        proto = "https" if port in [443, 8443] else "http"
        url = f"{proto}://www.{TARGET_DOMAIN}:{port}/"
        try:
            res = subprocess.run(
                ["curl", "-sI", "-m", "5",
                 "-H", DOORDASH_RULES["required_header"],
                 url],
                capture_output=True, text=True, timeout=8,
            )
            status = "OPEN" if res.stdout.strip() else "CLOSED/FILTERED"
            results.append(f"Port {port} ({proto}): {status}")
            if res.stdout.strip():
                # Extract server header
                for line in res.stdout.splitlines():
                    if line.lower().startswith(("server:", "x-powered-by:", "x-frame-options:")):
                        results.append(f"  → {line.strip()}")
        except Exception as exc:
            log(f"Port check failed for {port}/{proto}: {exc}", "DEBUG")
            results.append(f"Port {port} ({proto}): TIMEOUT")

        time.sleep(0.5)

    outfile.write_text("\n".join(results) + "\n")
    log(f"Checked {len(common_ports)} common ports passively")
    db_log("step_complete", "port_scan_passive",
           details={"ports_checked": len(common_ports)})

    # Feed service data to LLM
    analyze_step_output("port_scan_passive", [outfile])
    return True


def step_js_analysis():
    """Step 7: Extract JavaScript file URLs for analysis."""
    log("═══ STEP 7: JavaScript File Discovery ═══")
    db_log("step_start", "js_analysis", "curl")

    # Gather all URLs, filter for .js files
    js_urls = set()
    for url_file in TARGET_DIR.glob("0*_urls_*.txt"):
        if url_file.exists():
            for line in url_file.read_text().splitlines():
                line = line.strip()
                if re.search(r'\.js(\?|$)', line, re.IGNORECASE):
                    js_urls.add(line)

    # Also check main page for JS references
    try:
        res = subprocess.run(
            ["curl", "-sL", "-m", "15",
             "-H", DOORDASH_RULES["required_header"],
             "-A", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
             f"https://www.{TARGET_DOMAIN}"],
            capture_output=True, text=True, timeout=20,
        )
        if res.stdout:
            # Extract JS URLs from HTML
            for match in re.finditer(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', res.stdout):
                url = match.group(1)
                if url.startswith("//"):
                    url = "https:" + url
                elif url.startswith("/"):
                    url = f"https://www.{TARGET_DOMAIN}{url}"
                js_urls.add(url)
    except Exception as e:
        log(f"Error fetching main page: {e}", "WARN")

    outfile = TARGET_DIR / "07_js_files.txt"
    outfile.write_text("\n".join(sorted(js_urls)) + "\n")
    log(f"JavaScript files discovered: {len(js_urls)}")

    # Download a few key JS files for endpoint extraction (small ones only)
    js_content_dir = TARGET_DIR / "js_contents"
    js_content_dir.mkdir(exist_ok=True)

    downloaded = 0
    endpoints_found = set()

    for js_url in sorted(js_urls)[:30]:  # Limit to 30 files
        try:
            res = subprocess.run(
                ["curl", "-sL", "-m", "10",
                 "-H", DOORDASH_RULES["required_header"],
                 js_url],
                capture_output=True, text=True, timeout=15,
            )
            if res.stdout and len(res.stdout) < 500_000:  # Skip huge bundles
                # Save content
                safe_name = re.sub(r'[^\w.]', '_', js_url.split("/")[-1].split("?")[0])[:80]
                js_file = js_content_dir / safe_name
                js_file.write_text(res.stdout)
                downloaded += 1

                # Extract API endpoints from JS
                api_patterns = [
                    r'["\'](/api/[^\s"\'<>]+)["\']',
                    r'["\'](/v\d+/[^\s"\'<>]+)["\']',
                    r'["\'](/graphql[^\s"\'<>]*)["\']',
                    r'fetch\s*\(\s*["\']([^\s"\'<>]+)["\']',
                    r'axios\.[a-z]+\s*\(\s*["\']([^\s"\'<>]+)["\']',
                    r'\.get\s*\(\s*["\']([^\s"\'<>]+)["\']',
                    r'\.post\s*\(\s*["\']([^\s"\'<>]+)["\']',
                    r'\.put\s*\(\s*["\']([^\s"\'<>]+)["\']',
                    r'\.delete\s*\(\s*["\']([^\s"\'<>]+)["\']',
                    r'["\']https?://[^\s"\'<>]+doordash[^\s"\'<>]+["\']',
                ]
                for pat in api_patterns:
                    for m in re.finditer(pat, res.stdout):
                        endpoints_found.add(m.group(1) if m.lastindex else m.group(0))

            time.sleep(0.5)  # Rate limit
        except Exception as exc:
            log(f"JS file processing failed: {exc}", "DEBUG")

    # Save extracted endpoints
    ep_file = TARGET_DIR / "07_js_endpoints.txt"
    ep_file.write_text("\n".join(sorted(endpoints_found)) + "\n")
    log(f"Downloaded {downloaded} JS files, extracted {len(endpoints_found)} endpoints")

    # ── Store JS endpoints in DB ──
    if _db:
        eps = [{"url": ep, "source": "js_analysis", "is_interesting": 1,
                "category": "js_endpoint"} for ep in endpoints_found]
        inserted = _db.store_endpoints(_target_id, _scan_id, eps)
        log(f"💾 {inserted} JS endpoints → DB")

    db_log("step_complete", "js_analysis",
           details={"js_files": len(js_urls), "endpoints": len(endpoints_found)})

    # Feed JS data to LLM
    analyze_step_output("js_analysis", [
        TARGET_DIR / "07_js_files.txt",
        ep_file,
    ])
    return True


def step_param_discovery():
    """Step 8: Parameter discovery from all collected URLs."""
    log("═══ STEP 8: Parameter Discovery ═══")
    db_log("step_start", "param_discovery")

    all_params = {}  # param_name -> list of URLs where seen

    for url_file in TARGET_DIR.glob("0*_urls_*.txt"):
        if not url_file.exists():
            continue
        for line in url_file.read_text().splitlines():
            line = line.strip()
            if "?" not in line:
                continue
            query = line.split("?", 1)[1]
            for pair in query.split("&"):
                if "=" in pair:
                    param = pair.split("=", 1)[0].strip()
                    if param and len(param) < 50:
                        if param not in all_params:
                            all_params[param] = []
                        if len(all_params[param]) < 5:  # keep max 5 example URLs
                            all_params[param].append(line)

    # Write structured param report
    outfile = TARGET_DIR / "08_parameters.txt"
    lines = [f"Parameter Discovery Report for {TARGET_DOMAIN}",
             f"{'='*60}", f"Total unique parameters: {len(all_params)}", ""]

    # Sort by frequency (most common first)
    sorted_params = sorted(all_params.items(), key=lambda x: len(x[1]), reverse=True)

    # Flag interesting parameters (potential vuln vectors)
    interesting_keywords = [
        "id", "user", "account", "email", "password", "token", "key", "secret",
        "redirect", "url", "next", "return", "callback", "goto", "dest",
        "file", "path", "dir", "page", "template", "include", "load",
        "query", "search", "q", "s", "cmd", "exec", "command",
        "role", "admin", "type", "action", "method",
        "price", "amount", "quantity", "discount", "coupon",
        "order", "payment", "card", "number",
    ]

    for param, urls in sorted_params:
        is_interesting = any(kw in param.lower() for kw in interesting_keywords)
        marker = " ⚠️  INTERESTING" if is_interesting else ""
        lines.append(f"\n[PARAM] {param}  (seen {len(urls)}x){marker}")
        for url in urls[:3]:
            lines.append(f"  → {url[:200]}")

    outfile.write_text("\n".join(lines) + "\n")
    log(f"Parameters catalogued: {len(all_params)}")

    # ── Store parameters in DB ──
    if _db:
        interesting_keywords = [
            "id", "user", "account", "email", "password", "token", "key", "secret",
            "redirect", "url", "next", "return", "callback", "goto", "dest",
            "file", "path", "dir", "page", "template", "include", "load",
            "query", "search", "q", "s", "cmd", "exec", "command",
            "role", "admin", "type", "action", "method",
            "price", "amount", "quantity", "discount", "coupon",
        ]
        params = []
        for pname, urls in all_params.items():
            is_int = any(kw in pname.lower() for kw in interesting_keywords)
            params.append({
                "name": pname, "sample_urls": urls[:5],
                "is_interesting": 1 if is_int else 0,
            })
        inserted = _db.store_parameters(_target_id, _scan_id, params)
        log(f"💾 {inserted} parameters → DB")

    db_log("step_complete", "param_discovery",
           details={"params_total": len(all_params)})

    analyze_step_output("param_discovery", [TARGET_DIR / "08_parameters.txt"])
    return True


def step_header_analysis():
    """Step 9: Security header analysis on in-scope targets."""
    log("═══ STEP 9: Security Header Analysis ═══")
    db_log("step_start", "header_analysis")

    headers_file = TARGET_DIR / "05_tech_headers.txt"
    if not headers_file.exists():
        log("No header data found, skipping", "WARN")
        return False

    content = headers_file.read_text()
    results = []
    results.append(f"Security Header Analysis for {TARGET_DOMAIN}")
    results.append("=" * 60)

    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-frame-options": "X-Frame-Options",
        "x-content-type-options": "X-Content-Type-Options",
        "x-xss-protection": "X-XSS-Protection",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
        "access-control-allow-origin": "CORS",
        "set-cookie": "Cookies",
        "server": "Server",
        "x-powered-by": "X-Powered-By",
    }

    # Parse each target block
    blocks = content.split("=" * 60)
    for block in blocks:
        if "TARGET:" not in block:
            continue
        target_line = [l for l in block.splitlines() if "TARGET:" in l]
        if not target_line:
            continue
        target = target_line[0].replace("TARGET:", "").strip()
        results.append(f"\n{'─'*60}")
        results.append(f"Target: {target}")

        found = {}
        missing = []
        for line in block.splitlines():
            line_lower = line.lower().strip()
            for hdr, name in security_headers.items():
                if line_lower.startswith(hdr + ":"):
                    found[name] = line.split(":", 1)[1].strip()

        for hdr, name in security_headers.items():
            if name not in found:
                missing.append(name)

        if found:
            results.append("  Present headers:")
            for name, value in found.items():
                results.append(f"    ✓ {name}: {value[:100]}")

                # Flag issues
                if name == "CORS" and value == "*":
                    results.append(f"      ⚠️  WILDCARD CORS - Potential misconfiguration!")
                if name == "Cookies":
                    if "secure" not in value.lower():
                        results.append(f"      ⚠️  Missing Secure flag on cookie!")
                    if "httponly" not in value.lower():
                        results.append(f"      ⚠️  Missing HttpOnly flag on cookie!")
                    if "samesite" not in value.lower():
                        results.append(f"      ⚠️  Missing SameSite attribute!")

        if missing:
            results.append("  Missing security headers:")
            for name in missing:
                results.append(f"    ✗ {name}")

    outfile = TARGET_DIR / "09_security_headers.txt"
    outfile.write_text("\n".join(results) + "\n")
    log("Security header analysis complete")

    # ── Store header-based findings in DB ──
    if _db:
        for line in results:
            if "⚠️" in line:
                vuln = {
                    "title": line.strip().replace("⚠️", "").strip(),
                    "category": "misconfiguration",
                    "severity": "medium" if "CORS" in line else "low",
                    "source": "header_analysis",
                    "evidence": line.strip(),
                }
                _db.store_vulnerability(_target_id, _scan_id, vuln)

    db_log("step_complete", "header_analysis")

    # Feed security header analysis to LLM
    analyze_step_output("header_analysis", [outfile])
    return True


def step_scope_filter():
    """Step 10: Final consolidation - combine all data, filter scope, create summary."""
    log("═══ STEP 10: Final Consolidation & Summary ═══")
    db_log("step_start", "scope_filter")

    summary = {
        "target": TARGET_DOMAIN,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "recon_type": "PASSIVE ONLY",
        "program": PROGRAM_NAME,
        "data_files": {},
        "stats": {},
    }

    # Count data in each file
    for f in sorted(TARGET_DIR.glob("*.txt")):
        lines = len(f.read_text().strip().splitlines())
        summary["data_files"][f.name] = lines

    # Key stats
    sub_file = TARGET_DIR / "01_subdomains_inscope.txt"
    if sub_file.exists():
        summary["stats"]["subdomains_inscope"] = len(sub_file.read_text().strip().splitlines())

    url_file = TARGET_DIR / "03_urls_clean.txt"
    if url_file.exists():
        summary["stats"]["urls_unique"] = len(url_file.read_text().strip().splitlines())

    int_file = TARGET_DIR / "03_urls_interesting.txt"
    if int_file.exists():
        summary["stats"]["urls_interesting"] = len(int_file.read_text().strip().splitlines())

    js_file = TARGET_DIR / "07_js_endpoints.txt"
    if js_file.exists():
        summary["stats"]["js_endpoints"] = len(js_file.read_text().strip().splitlines())

    param_file = TARGET_DIR / "08_parameters.txt"
    if param_file.exists():
        summary["stats"]["parameters"] = len([
            l for l in param_file.read_text().splitlines() if l.startswith("[PARAM]")
        ])

    # Write JSON summary
    summary_file = TARGET_DIR / "10_recon_summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Write human-readable summary
    txt_summary = TARGET_DIR / "10_recon_summary.txt"
    lines = [
        f"╔{'═'*58}╗",
        f"║  BBHunter Passive Recon Summary                          ║",
        f"╠{'═'*58}╣",
        f"║  Target: {TARGET_DOMAIN:<48}║",
        f"║  Program: HackerOne DoorDash                             ║",
        f"║  Type: PASSIVE ONLY (no scanners per program rules)      ║",
        f"║  Date: {summary['timestamp'][:19]:<50}║",
        f"╠{'═'*58}╣",
    ]
    for key, val in summary["stats"].items():
        label = key.replace("_", " ").title()
        lines.append(f"║  {label}: {str(val):<47}║")
    lines.append(f"╠{'═'*58}╣")
    lines.append(f"║  Data Files:                                             ║")
    for fname, count in summary["data_files"].items():
        lines.append(f"║    {fname}: {count} lines{' '*(41-len(fname)-len(str(count)))}║")
    lines.append(f"╚{'═'*58}╝")

    txt_summary.write_text("\n".join(lines) + "\n")
    log("Recon summary generated")

    # ── Store final stats in DB ──
    if _db:
        db_stats = _db.get_stats(_target_id)
        _db.update_scan(_scan_id, "completed",
                            steps=list(STEPS.keys()),
                            stats=db_stats)
        log(f"💾 DB Stats: {db_stats.get('assets',0)} assets, "
            f"{db_stats.get('endpoints',0)} endpoints, "
            f"{db_stats.get('parameters',0)} params, "
            f"{db_stats.get('vulnerabilities',0)} vulns, "
            f"{db_stats.get('llm_chunks',0)} LLM chunks")

    db_log("step_complete", "scope_filter")

    # Feed final summary to LLM for big-picture analysis
    analyze_step_output("scope_filter", [txt_summary])
    return True


# ─────────────────────────────────────────────────────────────
#  Step registry
# ─────────────────────────────────────────────────────────────

STEPS = {
    "subdomain_enum":    step_subdomain_enum,
    "amass_enum":        step_amass_enum,
    "dns_resolution":    step_dns_resolution,
    "httpx_probe":       step_httpx_probe,
    "url_discovery":     step_url_discovery,
    "wayback_urls":      step_wayback_urls,
    "katana_crawl":      step_katana_crawl,
    "hakrawler":         step_hakrawler,
    "tech_detection":    step_tech_detection,
    "port_scan_passive": step_port_scan_passive,
    "js_analysis":       step_js_analysis,
    "param_discovery":   step_param_discovery,
    "header_analysis":   step_header_analysis,
    "scope_filter":      step_scope_filter,
}


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    global LLM_ENABLED, _step_timeout
    import argparse
    parser = argparse.ArgumentParser(description="BBHunter Passive Recon Pipeline")
    parser.add_argument("--step", type=str, help="Run a single step")
    parser.add_argument("--list", action="store_true", help="List all steps")
    parser.add_argument("--from-step", type=str, help="Resume from a specific step")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM analysis after each step")
    parser.add_argument("--engines", action="store_true",
                        help="Run bbhunter engines after recon (surface, scanner, analysis, etc.)")
    parser.add_argument("--no-engines", action="store_true",
                        help="Skip bbhunter engine phase even if --engines was default")
    parser.add_argument("--step-timeout", type=int, default=None,
                        help=f"Max seconds per step (0=no limit, default={STEP_TIMEOUT})")
    args = parser.parse_args()

    if args.no_llm:
        LLM_ENABLED = False

    if args.step_timeout is not None:
        _step_timeout = args.step_timeout

    if args.list:
        table = Table(title="Available Recon Steps", box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Step Name", style="cyan bold")
        for i, name in enumerate(STEPS, 1):
            table.add_row(str(i), name)
        console.print(table)
        return

    ensure_dirs()

    # ── Initialize Database + Safety Gate ──
    init_db_and_safety()

    console.print(Panel.fit(
        f"[bold blue]🎯 BBHunter — Passive Recon Pipeline[/bold blue]\n\n"
        f"  Target:  [cyan]{TARGET_DOMAIN}[/cyan]\n"
        f"  Mode:    [green]PASSIVE ONLY[/green] (no active scanners)\n"
        f"  DB:      [dim]{_db.db_path if _db else 'N/A'}[/dim]\n"
        f"  LLM:     {'[green]ON[/green]' if LLM_ENABLED else '[red]OFF[/red]'}",
        title="hunt.py",
        style="blue",
    ))

    if args.step:
        if args.step not in STEPS:
            log(f"Unknown step: {args.step}. Use --list to see available steps.", "ERROR")
            sys.exit(1)
        STEPS[args.step]()
        return

    # ── Build the list of steps to run ──
    start_running = not args.from_step
    steps_to_run = []
    for name, func in STEPS.items():
        if args.from_step and name == args.from_step:
            start_running = True
        if start_running:
            steps_to_run.append((name, func))
        else:
            log(f"Skipping {name}...")

    total_start = time.time()
    step_results: list[dict] = []

    # ── Run steps with a Rich progress bar + ETA ──
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•  ETA"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Recon pipeline", total=len(steps_to_run))

        for name, func in steps_to_run:
            progress.update(task, description=f"[cyan]{name}[/cyan]")
            step_start = time.time()
            status = run_step_with_timeout(name, func, _step_timeout)
            elapsed = time.time() - step_start
            step_results.append({"name": name, "elapsed": elapsed, "status": status})
            if status == "⏭":
                log(f"Step {name} timed out after {elapsed:.1f}s — skipping to next")
            else:
                log(f"Step {name} completed in {elapsed:.1f}s")
            progress.advance(task)
            time.sleep(1)  # Brief pause between steps

    total_elapsed = time.time() - total_start

    # ── Final DB stats ──
    if _db:
        stats = _db.get_stats(_target_id)
        _db.update_scan(_scan_id, "completed", stats=stats)
        db_log("pipeline_complete", details={
            "duration_s": round(total_elapsed, 1), "stats": stats})

    # ── Pretty summary table ──
    summary = Table(title="Recon Steps Summary", box=box.ROUNDED)
    summary.add_column("#", style="dim", width=4)
    summary.add_column("Step", style="cyan")
    summary.add_column("Status", justify="center")
    summary.add_column("Duration", justify="right", style="yellow")
    for i, r in enumerate(step_results, 1):
        st = "[green]✓[/green]" if r["status"] == "✓" else \
             "[yellow]⏭[/yellow]" if r["status"] == "⏭" else "[red]✗[/red]"
        summary.add_row(str(i), r["name"], st, f"{r['elapsed']:.1f}s")
    summary.add_section()
    summary.add_row("", "[bold]TOTAL[/bold]", "", f"[bold]{total_elapsed:.1f}s[/bold]")
    console.print(summary)

    if _db:
        s = _db.get_stats(_target_id)
        db_table = Table(title="DB Summary", box=box.SIMPLE)
        for k, v in s.items():
            db_table.add_column(k.replace("_", " ").title(), justify="right", style="cyan")
        db_table.add_row(*[str(v) for v in s.values()])
        console.print(db_table)

    log(f"Data saved to: {TARGET_DIR}")

    # ── Run bbhunter engines if requested ──
    if args.engines and not args.no_engines:
        console.print(Panel("[bold]Starting bbhunter engine pipeline…[/bold]", style="magenta"))
        try:
            import asyncio
            from engine_bridge import run_all_engines
            asyncio.run(run_all_engines())
        except Exception as e:
            log(f"Engine pipeline failed: {e}", "ERROR")
            db_log("engine_pipeline_error", details={"error": str(e)}, level="ERROR")
    elif not args.step:  # only show hint if running full pipeline
        console.print("\n[dim]💡 Tip: Run with --engines to activate bbhunter engines"
                       " (surface, scanner, analysis, payloads, reporting)[/dim]")

    console.print(Panel.fit(
        f"[green bold]✅ Recon complete in {total_elapsed:.0f}s ({total_elapsed/60:.1f}m)[/green bold]\n\n"
        f"  Data:  [cyan]{TARGET_DIR}[/cyan]\n"
        f"  Next:  [cyan]python3 scripts/generate_report.py[/cyan]",
        title="Done",
        style="green",
    ))


if __name__ == "__main__":
    main()

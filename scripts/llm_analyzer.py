#!/usr/bin/env python3
"""
BBHunter - LLM Chunk Analyzer
===============================
Processes recon data files CHUNK BY CHUNK through a local LLM (Ollama).
Designed for low-VRAM GPUs — sends small chunks to avoid OOM.

How it works:
  1. Reads each data file from data/<target>/
  2. Splits into chunks of ~3000 chars (~750 tokens)
  3. Sends each chunk to Ollama with a security-analysis prompt
  4. Stores per-chunk analysis in llm_analysis/<target>/
  5. Once all chunks processed, merges into a per-file summary

Usage:
    python3 scripts/llm_analyzer.py                    # analyze all files
    python3 scripts/llm_analyzer.py --file 03_urls_interesting.txt
    python3 scripts/llm_analyzer.py --resume            # skip already processed
"""

import json
import sys
import time
import hashlib
import argparse
import requests
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (
    TARGET_DOMAIN, TARGET_DIR, TARGET_LLM_DIR,
    LLM_API_URL, LLM_MODEL, PROGRAM_NAME,
    CHUNK_SIZE_CHARS, CHUNK_OVERLAP_CHARS,
    MAX_RESPONSE_TOKENS, LLM_TEMPERATURE,
    LLM_REQUEST_TIMEOUT, DOORDASH_RULES,
    ensure_dirs,
    LLM_CHUNK_TIMEOUT, MAX_CONSECUTIVE_FAILURES,
    LLM_NUM_CTX, LLM_NUM_BATCH,
)

# ── Timeout / Skip Settings (can be overridden at runtime) ──
_chunk_timeout: int = LLM_CHUNK_TIMEOUT  # 0 = use LLM_REQUEST_TIMEOUT
_max_consecutive_failures: int = MAX_CONSECUTIVE_FAILURES

# ── DB integration (optional, works without it too) ──
_db_instance = None
_target_id = ""
_scan_id = ""

def init_analyzer_db():
    """Initialize DB for standalone llm_analyzer runs."""
    global _db_instance, _target_id, _scan_id
    try:
        from db_manager import get_db
        _db_instance = get_db()
        _target_id = _db_instance.get_target_id(TARGET_DOMAIN)
        if not _target_id:
            _target_id = _db_instance.upsert_target(TARGET_DOMAIN, PROGRAM_NAME)
        _scan_id = _db_instance.start_scan(_target_id, "llm_analysis")
        print(f"  💾 DB connected: {_db_instance.db_path}")
    except Exception as e:
        print(f"  ⚠️  DB not available (non-fatal): {e}")


# ─────────────────────────────────────────────────────────────
#  Chunking Engine
# ─────────────────────────────────────────────────────────────

def chunk_text(text: str, chunk_size: int = CHUNK_SIZE_CHARS,
               overlap: int = CHUNK_OVERLAP_CHARS) -> list[dict]:
    """
    Split text into overlapping chunks. Tries to split on newlines
    to avoid cutting in the middle of a line.
    Returns list of {index, start, end, text, hash}
    """
    if not text.strip():
        return []

    chunks = []
    start = 0
    idx = 0

    while start < len(text):
        end = min(start + chunk_size, len(text))

        # Try to end at a newline boundary
        if end < len(text):
            newline_pos = text.rfind("\n", start + chunk_size // 2, end)
            if newline_pos > start:
                end = newline_pos + 1

        chunk_text_str = text[start:end]
        chunk_hash = hashlib.md5(chunk_text_str.encode()).hexdigest()[:12]

        chunks.append({
            "index": idx,
            "start": start,
            "end": end,
            "text": chunk_text_str,
            "hash": chunk_hash,
            "char_count": len(chunk_text_str),
            "line_count": chunk_text_str.count("\n"),
        })

        idx += 1
        start = end - overlap if end < len(text) else end

    return chunks


# ─────────────────────────────────────────────────────────────
#  LLM Client (Ollama API)
# ─────────────────────────────────────────────────────────────

def query_llm(prompt: str, system_prompt: str = "", timeout_override: int = 0, max_retries: int = 3) -> dict:
    """
    Send a prompt to the local Ollama LLM (dolphin-llama3:8b).
    No thinking mode — direct responses, all tokens go to output.
    Returns {response, tokens_eval, duration_s, success}

    timeout_override: if >0, use this instead of default. 0 means use
    _chunk_timeout (if >0) or LLM_REQUEST_TIMEOUT.

    Retries transient failures with exponential backoff (1s, 2s, 4s …).
    """
    effective_timeout = timeout_override or _chunk_timeout or LLM_REQUEST_TIMEOUT
    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": LLM_TEMPERATURE,
            "num_predict": MAX_RESPONSE_TOKENS,
            "num_ctx": LLM_NUM_CTX,
            "num_batch": LLM_NUM_BATCH,
        },
    }
    if system_prompt:
        payload["system"] = system_prompt

    last_error: str = ""
    for attempt in range(1, max_retries + 1):
        start = time.time()
        try:
            resp = requests.post(
                f"{LLM_API_URL}/api/generate",
                json=payload,
                timeout=effective_timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            elapsed = time.time() - start

            # Prefer 'response'; fall back to 'thinking' if response is empty
            response_text = data.get("response", "")
            if not response_text.strip():
                response_text = data.get("thinking", "")

            if response_text.strip():
                return {
                    "response": response_text,
                    "tokens_eval": data.get("eval_count", 0),
                    "tokens_prompt": data.get("prompt_eval_count", 0),
                    "duration_s": round(elapsed, 2),
                    "done_reason": data.get("done_reason", ""),
                    "success": True,
                }
            last_error = "Empty response from LLM"
        except requests.exceptions.ConnectionError:
            last_error = "Cannot connect to Ollama. Is it running?"
        except requests.exceptions.Timeout:
            last_error = f"LLM timeout after {effective_timeout}s"
        except Exception as e:
            last_error = str(e)

        # Exponential backoff before retry
        if attempt < max_retries:
            backoff = 2 ** (attempt - 1)
            time.sleep(backoff)

    return {"response": "", "success": False, "error": last_error}


def check_llm_health() -> bool:
    """Verify LLM is running and model is loaded."""
    try:
        resp = requests.get(f"{LLM_API_URL}/api/tags", timeout=5)
        models = [m["name"] for m in resp.json().get("models", [])]
        if LLM_MODEL in models or any(LLM_MODEL.split(":")[0] in m for m in models):
            print(f"  ✓ LLM ready: {LLM_MODEL}")
            return True
        print(f"  ✗ Model {LLM_MODEL} not found. Available: {models}")
        return False
    except Exception as e:
        print(f"  ✗ Cannot reach Ollama at {LLM_API_URL}: {e}")
        return False


# ─────────────────────────────────────────────────────────────
#  Security Analysis Prompts
# ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an elite bug bounty hunter with deep expertise in web application security, 
cloud infrastructure, and API hacking. You are analyzing passive reconnaissance data from a 
HackerOne program. Your analysis must be methodical, precise, and actionable.

## Your Analysis Methodology (follow this exact order):

### PASS 1 — DISCOVERY
Scan the data for anything security-relevant:
- Subdomains/endpoints that suggest internal, staging, dev, or admin infrastructure
- API endpoints with parameters that may be injectable or lead to IDOR
- Technology stack indicators (frameworks, servers, CDNs, WAFs)
- Tokens, keys, secrets, credentials, or anything resembling sensitive data
- Unusual HTTP headers, status codes, or response patterns
- Cloud service indicators (S3 buckets, Azure blobs, GCP resources)
- JavaScript files or endpoints that may expose internal APIs

### PASS 2 — VALIDATION
For each item found in Pass 1:
- Could this be a false positive? (e.g., honeypot, intentional exposure, CDN artifact)
- What is the confidence level? (CONFIRMED / LIKELY / POSSIBLE / SPECULATIVE)
- Is this in scope per HackerOne rules?

### PASS 3 — ATTACK CHAIN REASONING
Connect findings into potential attack chains:
- Can finding A + finding B be combined for higher impact?
- What is the realistic exploitation path?
- What would an attacker do with this information?

## Output Format — For each finding output:

**[SEVERITY] Finding Title**
- **Target**: exact URL / domain / endpoint (REQUIRED — copy from data)
- **Confidence**: CONFIRMED / LIKELY / POSSIBLE
- **Category**: One of: IDOR, XSS, SSRF, SQLi, Auth Bypass, Info Disclosure, 
  Misconfiguration, Open Redirect, Business Logic, Subdomain Takeover, 
  API Security, CORS, CSRF, Insecure Deserialization, Command Injection, 
  Path Traversal, JWT Issues, Cloud Misconfiguration, Other
- **What**: Clear description of the finding
- **Why**: Security implication and potential impact
- **Evidence**: The specific data from this chunk that proves it
- **Chain Potential**: Can this combine with other vulns? How?
- **Manual Test**: Exact steps to confirm this finding
- **CVSS Estimate**: X.X (Base Score estimate)

## Rules:
- NEVER fabricate URLs or data — only cite what's in the chunk
- ALWAYS include the exact URL/domain from the data
- Focus on ACTIONABLE findings — skip informational noise
- Think like an attacker: what would you test first?
- Consider business context: payment flows, auth, PII exposure are high-value"""


def get_analysis_prompt(filename: str, chunk_idx: int, total_chunks: int,
                        chunk_text: str) -> str:
    """Build the analysis prompt for a specific data chunk."""

    file_context = {
        "01_subdomains": (
            "subdomain enumeration results — look for: dev/staging/admin/internal subdomains, "
            "cloud service subdomains (*.s3.amazonaws.com, *.azurewebsites.net), CNAME records "
            "pointing to decommissioned services (subdomain takeover), wildcard DNS, zone transfers"
        ),
        "02_dns": (
            "DNS resolution data — look for: internal/RFC1918 IPs leaked in DNS, cloud provider IPs "
            "(identify hosting), CDN/WAF bypass via direct-to-origin IPs, CNAME chains revealing "
            "infrastructure, TXT records with SPF/DKIM/DMARC misconfigs, MX records revealing email provider"
        ),
        "02b_httpx": (
            "live HTTP probing results — look for: status codes revealing access control (401/403 on "
            "interesting paths, 200 on admin panels), redirect chains, different responses per host, "
            "technology fingerprints in headers (X-Powered-By, Server, X-AspNet-Version)"
        ),
        "03_urls": (
            "discovered URLs — HIGH VALUE: look for: API endpoints with parameters (/api/v1/users?id=), "
            "admin panels, debug endpoints (/debug, /trace, /actuator), file upload paths, "
            "OAuth/SSO endpoints, webhook URLs, GraphQL endpoints, sensitive file paths (.env, .git)"
        ),
        "04_wayback": (
            "Wayback Machine / historical URLs — look for: removed endpoints still accessible, "
            "old API versions (/v1/ when /v2/ is current), leaked parameters no longer in UI, "
            "backup files (.bak, .old, .swp), config files, old auth flows"
        ),
        "04b_katana": (
            "Katana crawler results — look for: dynamically discovered endpoints not in static recon, "
            "form action URLs, API calls from JavaScript, hidden parameters, file upload endpoints"
        ),
        "04c_hakrawler": (
            "Hakrawler results — look for: same as katana but may find different endpoints, "
            "form actions, JS-discovered APIs, linked resources"
        ),
        "05_tech": (
            "HTTP response headers & technology detection — look for: missing security headers "
            "(CSP, HSTS, X-Frame-Options), server version disclosure, outdated framework versions "
            "with known CVEs, CORS misconfiguration (Access-Control-Allow-Origin: *), "
            "cookie issues (missing Secure/HttpOnly/SameSite flags)"
        ),
        "06_services": (
            "service/port scan results — look for: exposed admin services (Redis, MongoDB, "
            "Elasticsearch, Kibana), development tools (Jupyter, phpMyAdmin), version-specific "
            "vulnerabilities, services that shouldn't be public"
        ),
        "07_js": (
            "JavaScript files and extracted endpoints — HIGH VALUE: look for: hardcoded API keys, "
            "AWS credentials, internal API endpoints, authentication logic, hidden admin routes, "
            "debug endpoints, websocket URLs, internal service URLs, source maps"
        ),
        "08_param": (
            "discovered parameters — HIGH VALUE: look for: ID parameters (user_id, account_id → IDOR), "
            "URL parameters (redirect, callback, url → SSRF/Open Redirect), search/query params → XSS/SQLi, "
            "file parameters → LFI/Path Traversal, hidden parameters, debug parameters (debug=1)"
        ),
        "09_security": (
            "security header analysis — look for: complete missing header inventory, CORS policy "
            "weaknesses, CSP bypass opportunities (unsafe-inline, unsafe-eval, data: URIs), "
            "cookie security issues, cache-control on sensitive endpoints, HSTS preload status"
        ),
        "10_recon": (
            "recon summary / consolidated data — look for: cross-referencing opportunities between "
            "different data sources, patterns across multiple subdomains, infrastructure-wide issues"
        ),
    }

    context_hint = "reconnaissance data"
    for prefix, hint in file_context.items():
        if filename.startswith(prefix):
            context_hint = hint
            break

    # Build cross-reference context from previously analyzed files
    cross_ref = ""
    try:
        llm_dir = Path(__file__).resolve().parent.parent / "llm_analysis" / TARGET_DOMAIN.replace(".", "_")
        if llm_dir.exists():
            prev_summaries = []
            for d in sorted(llm_dir.iterdir()):
                if d.is_dir() and not d.name.startswith(filename.replace(".txt", "")):
                    merged = d / "_merged_analysis.txt"
                    if merged.exists():
                        text = merged.read_text()[:800]  # First 800 chars as context
                        if text.strip():
                            prev_summaries.append(f"[{d.name}]: {text[:400]}")
            if prev_summaries:
                cross_ref = (
                    "\n\n## Cross-Reference Context (findings from other recon files):\n"
                    + "\n".join(prev_summaries[:5])
                    + "\n\nUse this context to identify connections between this chunk's data "
                    "and previous findings. Look for attack chains that span multiple data sources."
                )
    except Exception as exc:
        logging.debug(f"Failed to build cross-reference context: {exc}")

    return f"""## Bug Bounty Recon Analysis — Multi-Pass
**Target:** {TARGET_DOMAIN} (HackerOne program)
**File:** {filename}
**Context:** This is {context_hint}
**Chunk:** {chunk_idx + 1} of {total_chunks}

Analyze this data chunk following your 3-pass methodology (Discovery → Validation → Attack Chains).
{cross_ref}

### Data to Analyze:

```
{chunk_text}
```

For EACH finding, output the structured format from your instructions.
If a finding connects to data from the cross-reference context, explicitly note the chain.
End your analysis with a "Priority Targets" section listing the top 3 items for immediate manual testing."""


# ─────────────────────────────────────────────────────────────
#  File Processing Pipeline
# ─────────────────────────────────────────────────────────────

def get_data_files() -> list[Path]:
    """Get all recon data files in processing order."""
    # Priority order: interesting URLs first, then params, then rest
    priority_prefixes = [
        "03_urls_interesting",
        "07_js_endpoints",
        "08_parameters",
        "09_security_headers",
        "05_tech_headers",
        "01_subdomains_inscope",
        "02_dns_resolved",
        "03_urls_clean",
        "04_wayback_clean",
        "04_wayback_params",
        "07_js_files",
        "06_services",
    ]

    files = []
    seen = set()
    for prefix in priority_prefixes:
        for f in TARGET_DIR.glob(f"{prefix}*"):
            if f.is_file() and f.suffix == ".txt" and f.name not in seen:
                files.append(f)
                seen.add(f.name)

    # Add any remaining .txt files
    for f in sorted(TARGET_DIR.glob("*.txt")):
        if f.name not in seen and f.stat().st_size > 0:
            files.append(f)
            seen.add(f.name)

    return files


def process_file(filepath: Path, resume: bool = False) -> dict:
    """
    Process a single recon data file through the LLM chunk by chunk.
    Returns analysis results.
    """
    filename = filepath.name
    file_output_dir = TARGET_LLM_DIR / filename.replace(".txt", "")
    file_output_dir.mkdir(parents=True, exist_ok=True)

    # State file to track progress
    state_file = file_output_dir / "_state.json"
    state = {"filename": filename, "chunks_total": 0, "chunks_done": 0, "analyses": []}

    if resume and state_file.exists():
        state = json.loads(state_file.read_text())
        if state.get("complete"):
            print(f"  ⏭  Already processed: {filename}")
            return state

    # Read and chunk the file
    content = filepath.read_text()
    if not content.strip():
        print(f"  ⏭  Empty file: {filename}")
        return state

    chunks = chunk_text(content)
    state["chunks_total"] = len(chunks)
    state["file_size"] = len(content)
    state["file_lines"] = content.count("\n")

    print(f"\n  📄 Processing: {filename}")
    print(f"     Size: {len(content):,} chars | {content.count(chr(10))} lines | {len(chunks)} chunks")
    if _chunk_timeout:
        print(f"     Chunk timeout: {_chunk_timeout}s | Skip after {_max_consecutive_failures} consecutive failures")

    consecutive_failures = 0

    for chunk in chunks:
        chunk_file = file_output_dir / f"chunk_{chunk['index']:03d}.json"

        # Skip already processed chunks on resume
        if resume and chunk_file.exists():
            print(f"     ⏭  Chunk {chunk['index']+1}/{len(chunks)} already done")
            consecutive_failures = 0  # reset on existing success
            continue

        # ── Check consecutive failure threshold ──
        if _max_consecutive_failures > 0 and consecutive_failures >= _max_consecutive_failures:
            remaining = len(chunks) - chunk["index"]
            print(f"\n     ⚠️  {consecutive_failures} consecutive failures — "
                  f"skipping remaining {remaining} chunks of {filename}")
            state["skipped_reason"] = (
                f"Skipped after {consecutive_failures} consecutive failures"
            )
            break

        print(f"     🔍 Chunk {chunk['index']+1}/{len(chunks)} "
              f"({chunk['char_count']} chars, {chunk['line_count']} lines)...", end="", flush=True)

        prompt = get_analysis_prompt(filename, chunk["index"], len(chunks), chunk["text"])
        result = query_llm(prompt, SYSTEM_PROMPT)

        # Save chunk analysis
        chunk_result = {
            "chunk_index": chunk["index"],
            "chunk_hash": chunk["hash"],
            "chunk_chars": chunk["char_count"],
            "chunk_lines": chunk["line_count"],
            "llm_response": result.get("response", ""),
            "tokens_prompt": result.get("tokens_prompt", 0),
            "tokens_eval": result.get("tokens_eval", 0),
            "duration_s": result.get("duration_s", 0),
            "success": result.get("success", False),
            "error": result.get("error", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        chunk_file.write_text(json.dumps(chunk_result, indent=2))

        # ── Store in DB if available ──
        if _db_instance and _target_id and _scan_id:
            try:
                _db_instance.store_llm_chunk(_target_id, _scan_id, {
                    "source_file": filename,
                    "chunk_index": chunk["index"],
                    "total_chunks": len(chunks),
                    "chunk_hash": chunk["hash"],
                    "chunk_chars": chunk["char_count"],
                    "chunk_lines": chunk["line_count"],
                    "prompt_text": prompt[:500],
                    "response_text": result.get("response", ""),
                    "tokens_prompt": result.get("tokens_prompt", 0),
                    "tokens_eval": result.get("tokens_eval", 0),
                    "duration_s": result.get("duration_s", 0),
                    "success": result.get("success", False),
                    "error": result.get("error", ""),
                    "llm_model": LLM_MODEL,
                })
            except Exception as exc:
                logging.debug(f"Failed to store chunk analysis in DB: {exc}")

        if result["success"]:
            print(f" ✓ ({result['duration_s']}s, {result.get('tokens_eval', 0)} tokens)")
            state["chunks_done"] = chunk["index"] + 1
            state["analyses"].append(chunk_result)
            consecutive_failures = 0  # reset on success
        else:
            consecutive_failures += 1
            print(f" ✗ Error: {result.get('error', 'unknown')}"
                  f" (failures: {consecutive_failures}/{_max_consecutive_failures})")

        # Save state after each chunk (for resume capability)
        state_file.write_text(json.dumps(state, indent=2))

        # Brief pause to let GPU cool
        time.sleep(1)

    # Merge all chunk analyses into one file
    merge_file = file_output_dir / "_merged_analysis.txt"
    merged_lines = [
        f"{'='*60}",
        f"LLM Analysis: {filename}",
        f"Target: {TARGET_DOMAIN}",
        f"Chunks: {len(chunks)} | Date: {datetime.now(timezone.utc).isoformat()[:19]}",
        f"{'='*60}\n",
    ]

    for chunk_f in sorted(file_output_dir.glob("chunk_*.json")):
        try:
            cdata = json.loads(chunk_f.read_text())
            if cdata.get("success") and cdata.get("llm_response"):
                merged_lines.append(f"\n--- Chunk {cdata['chunk_index']+1} ---")
                merged_lines.append(cdata["llm_response"])
        except Exception as exc:
            logging.debug(f"Failed to parse chunk data for merging: {exc}")

    merge_file.write_text("\n".join(merged_lines) + "\n")

    # ── Store merged analysis in DB ──
    if _db_instance and _target_id and _scan_id:
        try:
            _db_instance.store_llm_analysis(_target_id, _scan_id, {
                "source_file": filename,
                "merged_text": "\n".join(merged_lines),
                "chunks_total": len(chunks),
                "chunks_done": state.get("chunks_done", 0),
                "total_tokens": sum(
                    a.get("tokens_eval", 0) for a in state.get("analyses", [])),
                "total_duration_s": sum(
                    a.get("duration_s", 0) for a in state.get("analyses", [])),
            })
        except Exception as exc:
            logging.debug(f"Failed to store merged analysis in DB: {exc}")

    state["complete"] = True
    state_file.write_text(json.dumps(state, indent=2))

    print(f"  ✅ {filename}: {state['chunks_done']}/{len(chunks)} chunks analyzed")
    return state


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    global CHUNK_SIZE_CHARS, _chunk_timeout, _max_consecutive_failures

    parser = argparse.ArgumentParser(description="BBHunter LLM Chunk Analyzer")
    parser.add_argument("--file", type=str, help="Analyze a specific file only")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    parser.add_argument("--chunk-size", type=int, default=None, help="Chars per chunk")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be processed")
    parser.add_argument("--chunk-timeout", type=int, default=None,
                        help=f"Max seconds per LLM chunk (0=default, current={_chunk_timeout})")
    parser.add_argument("--max-failures", type=int, default=None,
                        help=f"Skip file after N consecutive chunk failures (0=never skip, current={_max_consecutive_failures})")
    args = parser.parse_args()

    # Override chunk size if specified
    if args.chunk_size is not None:
        CHUNK_SIZE_CHARS = args.chunk_size
    if args.chunk_timeout is not None:
        _chunk_timeout = args.chunk_timeout
    if args.max_failures is not None:
        _max_consecutive_failures = args.max_failures

    ensure_dirs()

    print(f"\n╔{'═'*58}╗")
    print(f"║  BBHunter LLM Chunk Analyzer                             ║")
    print(f"╠{'═'*58}╣")
    print(f"║  Target: {TARGET_DOMAIN:<48}║")
    print(f"║  LLM: {LLM_MODEL:<51}║")
    print(f"║  Chunk size: {CHUNK_SIZE_CHARS} chars (~{CHUNK_SIZE_CHARS//4} tokens)              ║")
    print(f"║  Max response: {MAX_RESPONSE_TOKENS} tokens                           ║")
    print(f"╚{'═'*58}╝\n")

    # Health check
    print("Checking LLM...")
    if not check_llm_health():
        print("\n⚠️  Start Ollama first: ollama serve")
        print(f"   Then pull model: ollama pull {LLM_MODEL}")
        sys.exit(1)

    # ── Initialize DB ──
    init_analyzer_db()

    # Get files to process
    if args.file:
        target_file = TARGET_DIR / args.file
        if not target_file.exists():
            print(f"File not found: {target_file}")
            sys.exit(1)
        files = [target_file]
    else:
        files = get_data_files()

    if not files:
        print("No data files found. Run hunt.py first.")
        sys.exit(1)

    # Dry run
    if args.dry_run:
        total_chars = 0
        total_chunks = 0
        print("Files to process:")
        for f in files:
            content = f.read_text()
            chunks = chunk_text(content)
            total_chars += len(content)
            total_chunks += len(chunks)
            print(f"  {f.name}: {len(content):,} chars → {len(chunks)} chunks")
        print(f"\nTotal: {total_chars:,} chars → {total_chunks} chunks")
        est_time = total_chunks * 30  # ~30s per chunk estimate
        print(f"Estimated time: ~{est_time//60}m {est_time%60}s")
        return

    # Process files
    print(f"\n📁 Processing {len(files)} data files...\n")
    total_start = time.time()
    all_results = []

    for i, f in enumerate(files, 1):
        print(f"\n{'─'*60}")
        print(f"[{i}/{len(files)}] {f.name}")
        result = process_file(f, resume=args.resume)
        all_results.append(result)

    elapsed = time.time() - total_start

    # Final summary
    summary = {
        "target": TARGET_DOMAIN,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "llm_model": LLM_MODEL,
        "chunk_size": CHUNK_SIZE_CHARS,
        "files_processed": len(all_results),
        "total_chunks": sum(r.get("chunks_total", 0) for r in all_results),
        "total_duration_s": round(elapsed, 2),
        "files": {r.get("filename", "?"): r.get("chunks_done", 0) for r in all_results},
    }

    summary_file = TARGET_LLM_DIR / "_analysis_summary.json"
    summary_file.write_text(json.dumps(summary, indent=2))

    print(f"\n\n{'='*60}")
    print(f"✅ LLM Analysis Complete!")
    print(f"   Files processed: {len(all_results)}")
    print(f"   Total chunks: {summary['total_chunks']}")
    print(f"   Duration: {elapsed:.0f}s ({elapsed/60:.1f}m)")
    print(f"   Results: {TARGET_LLM_DIR}")
    print(f"\n   Next: python3 scripts/generate_report.py")


if __name__ == "__main__":
    main()

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
    LLM_API_URL, LLM_MODEL,
    CHUNK_SIZE_CHARS, CHUNK_OVERLAP_CHARS,
    MAX_RESPONSE_TOKENS, LLM_TEMPERATURE,
    LLM_REQUEST_TIMEOUT, DOORDASH_RULES,
    ensure_dirs,
)

# ── DB integration (optional, works without it too) ──
_db_instance = None
_target_id = ""
_scan_run_id = ""

def init_analyzer_db():
    """Initialize DB for standalone llm_analyzer runs."""
    global _db_instance, _target_id, _scan_run_id
    try:
        from db_manager import get_db
        _db_instance = get_db()
        _target_id = _db_instance.get_target_id(TARGET_DOMAIN)
        if not _target_id:
            _target_id = _db_instance.upsert_target(TARGET_DOMAIN, "HackerOne - DoorDash")
        _scan_run_id = _db_instance.start_scan_run(_target_id, "llm_analysis")
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

def query_llm(prompt: str, system_prompt: str = "") -> dict:
    """
    Send a prompt to the local Ollama LLM (dolphin-llama3:8b).
    No thinking mode — direct responses, all tokens go to output.
    Returns {response, tokens_eval, duration_s, success}
    """
    payload = {
        "model": LLM_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": LLM_TEMPERATURE,
            "num_predict": MAX_RESPONSE_TOKENS,
            "num_ctx": 4096,         # dolphin-llama3 handles 8K, 4K is safe for 4GB VRAM
            "num_batch": 256,        # dolphin fits better in VRAM
        },
    }
    if system_prompt:
        payload["system"] = system_prompt

    start = time.time()
    try:
        resp = requests.post(
            f"{LLM_API_URL}/api/generate",
            json=payload,
            timeout=LLM_REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        elapsed = time.time() - start

        # Prefer 'response'; fall back to 'thinking' if response is empty
        response_text = data.get("response", "")
        if not response_text.strip():
            response_text = data.get("thinking", "")

        return {
            "response": response_text,
            "tokens_eval": data.get("eval_count", 0),
            "tokens_prompt": data.get("prompt_eval_count", 0),
            "duration_s": round(elapsed, 2),
            "done_reason": data.get("done_reason", ""),
            "success": bool(response_text.strip()),
        }
    except requests.exceptions.ConnectionError:
        return {"response": "", "success": False, "error": "Cannot connect to Ollama. Is it running?"}
    except requests.exceptions.Timeout:
        return {"response": "", "success": False, "error": f"LLM timeout after {LLM_REQUEST_TIMEOUT}s"}
    except Exception as e:
        return {"response": "", "success": False, "error": str(e)}


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

SYSTEM_PROMPT = """You are an expert bug bounty hunter analyzing reconnaissance data from a HackerOne program.
Your task: analyze the provided data chunk and identify potential security findings.

Focus on:
1. VULNERABILITIES: Anything that could be a security issue (misconfigs, exposed endpoints, sensitive data leaks)
2. INTERESTING TARGETS: Endpoints/subdomains worth deeper manual testing
3. ATTACK VECTORS: Possible attack chains or exploitation paths
4. INFORMATION DISCLOSURE: Leaked data, internal paths, API keys, tokens
5. BUSINESS LOGIC: Unusual patterns suggesting logic flaws
6. LIST: the domains and logics and vulnerabilities that you can find in the data

CRITICAL RULE: For EVERY finding you MUST include the exact URL, domain, or endpoint from the data that the finding refers to. Never give a finding without citing the specific link/URL/domain.

For each finding:
- State the finding clearly
- Cite the EXACT URL / domain / endpoint it refers to (copy it from the data)
- Explain WHY it's interesting from a security perspective
- Suggest what manual test to perform next
- Rate severity: CRITICAL / HIGH / MEDIUM / LOW / INFO

Be concise. Focus on actionable findings only. Skip noise."""


def get_analysis_prompt(filename: str, chunk_idx: int, total_chunks: int,
                        chunk_text: str) -> str:
    """Build the analysis prompt for a specific data chunk."""

    file_context = {
        "01_subdomains": "subdomain enumeration results - look for interesting subdomains (dev, staging, admin, api, internal)",
        "02_dns": "DNS resolution data - look for internal IPs, cloud services, CDNs, interesting CNAME records",
        "03_urls": "discovered URLs - look for sensitive endpoints, API routes, admin panels, debug pages, parameters",
        "04_wayback": "Wayback Machine historical URLs - look for old/removed endpoints, leaked paths, parameters",
        "05_tech": "HTTP response headers - look for technology stack, misconfigurations, missing security headers",
        "06_services": "service/port information - look for exposed services, version disclosure",
        "07_js": "JavaScript files and extracted API endpoints - look for hidden APIs, hardcoded secrets, internal routes",
        "08_param": "discovered parameters - look for injection points, IDOR params, auth bypass params",
        "09_security": "security header analysis - look for missing protections, CORS issues, cookie problems",
    }

    context_hint = "reconnaissance data"
    for prefix, hint in file_context.items():
        if filename.startswith(prefix):
            context_hint = hint
            break

    return f"""## Bug Bounty Recon Analysis
**Target:** {TARGET_DOMAIN} (HackerOne program)
**File:** {filename}
**Context:** This is {context_hint}
**Chunk:** {chunk_idx + 1} of {total_chunks}

Analyze this data chunk for security-relevant findings:

```
{chunk_text}
```

List ALL security-relevant findings. For each:
1. **Finding**: What you found
2. **URL/Link**: The EXACT URL, domain, or endpoint from the data this refers to (REQUIRED - copy it from the data above)
3. **Why interesting**: Security implication
4. **Next step**: What manual test to do
5. **Severity**: CRITICAL/HIGH/MEDIUM/LOW/INFO"""


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

    for chunk in chunks:
        chunk_file = file_output_dir / f"chunk_{chunk['index']:03d}.json"

        # Skip already processed chunks on resume
        if resume and chunk_file.exists():
            print(f"     ⏭  Chunk {chunk['index']+1}/{len(chunks)} already done")
            continue

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
        if _db_instance and _target_id and _scan_run_id:
            try:
                _db_instance.store_llm_chunk(_target_id, _scan_run_id, {
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
            except Exception:
                pass

        if result["success"]:
            print(f" ✓ ({result['duration_s']}s, {result.get('tokens_eval', 0)} tokens)")
            state["chunks_done"] = chunk["index"] + 1
            state["analyses"].append(chunk_result)
        else:
            print(f" ✗ Error: {result.get('error', 'unknown')}")

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
        except Exception:
            pass

    merge_file.write_text("\n".join(merged_lines) + "\n")

    # ── Store merged analysis in DB ──
    if _db_instance and _target_id and _scan_run_id:
        try:
            _db_instance.store_llm_analysis(_target_id, _scan_run_id, {
                "source_file": filename,
                "merged_text": "\n".join(merged_lines),
                "chunks_total": len(chunks),
                "chunks_done": state.get("chunks_done", 0),
                "total_tokens": sum(
                    a.get("tokens_eval", 0) for a in state.get("analyses", [])),
                "total_duration_s": sum(
                    a.get("duration_s", 0) for a in state.get("analyses", [])),
            })
        except Exception:
            pass

    state["complete"] = True
    state_file.write_text(json.dumps(state, indent=2))

    print(f"  ✅ {filename}: {state['chunks_done']}/{len(chunks)} chunks analyzed")
    return state


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    global CHUNK_SIZE_CHARS

    parser = argparse.ArgumentParser(description="BBHunter LLM Chunk Analyzer")
    parser.add_argument("--file", type=str, help="Analyze a specific file only")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    parser.add_argument("--chunk-size", type=int, default=None, help="Chars per chunk")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be processed")
    args = parser.parse_args()

    # Override chunk size if specified
    if args.chunk_size is not None:
        CHUNK_SIZE_CHARS = args.chunk_size

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

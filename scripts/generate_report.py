#!/usr/bin/env python3
"""
BBHunter - LLM Report Generator
=================================
Reads all LLM chunk analyses, sends them back through the LLM
to produce a consolidated professional bug bounty report.

The report is generated in chunks too (to stay within VRAM limits):
  1. Collect all per-file merged analyses
  2. Chunk the merged analyses
  3. Ask LLM to extract findings from each chunk
  4. Final pass: LLM consolidates all findings into one report
  5. Output: Markdown report + JSON findings

Usage:
    python3 scripts/generate_report.py
    python3 scripts/generate_report.py --format markdown
    python3 scripts/generate_report.py --format html
"""

import json
import sys
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (
    TARGET_DOMAIN, TARGET_DIR, TARGET_LLM_DIR, TARGET_REPORT_DIR,
    LLM_API_URL, LLM_MODEL, CHUNK_SIZE_CHARS,
    MAX_RESPONSE_TOKENS, LLM_TEMPERATURE, LLM_REQUEST_TIMEOUT,
    DOORDASH_RULES, ensure_dirs,
)
from llm_analyzer import query_llm, chunk_text, check_llm_health

# ── DB integration ──
_db = None
_target_id = ""
_scan_run_id = ""

def init_report_db():
    """Initialize DB for report generation."""
    global _db, _target_id, _scan_run_id
    try:
        from db_manager import get_db
        _db = get_db()
        _target_id = _db.get_target_id(TARGET_DOMAIN)
        if not _target_id:
            _target_id = _db.upsert_target(TARGET_DOMAIN)
        _scan_run_id = _db.start_scan_run(_target_id, "report_generation")
        print(f"  💾 DB connected: {_db.db_path}")
    except Exception as e:
        print(f"  ⚠️  DB not available: {e}")


# ─────────────────────────────────────────────────────────────
#  Phase 1: Collect all LLM analyses
# ─────────────────────────────────────────────────────────────

def collect_analyses() -> list[dict]:
    """Collect all merged LLM analysis files (from DB first, fallback to files)."""
    analyses = []

    # Try DB first
    if _db and _target_id:
        db_analyses = _db.get_llm_analyses(_target_id)
        if db_analyses:
            print(f"  📦 Loaded {len(db_analyses)} analyses from DB")
            for a in db_analyses:
                if a.get("merged_text"):
                    analyses.append({
                        "source_file": a["source_file"],
                        "content": a["merged_text"],
                        "size": len(a["merged_text"]),
                        "from_db": True,
                    })
            if analyses:
                return analyses

    # Fallback to file system
    for analysis_dir in sorted(TARGET_LLM_DIR.iterdir()):
        if not analysis_dir.is_dir():
            continue
        merged_file = analysis_dir / "_merged_analysis.txt"
        if merged_file.exists():
            content = merged_file.read_text().strip()
            if content:
                analyses.append({
                    "source_file": analysis_dir.name,
                    "content": content,
                    "size": len(content),
                })

    return analyses


# ─────────────────────────────────────────────────────────────
#  Phase 2: Extract structured findings chunk by chunk
# ─────────────────────────────────────────────────────────────

EXTRACT_PROMPT = """You are consolidating bug bounty analysis findings.

Below is a chunk of LLM analysis output from reconnaissance on {domain}.
Extract ALL security findings into a structured list.

For each finding, output EXACTLY this format:
---FINDING---
Title: <concise title>
Severity: <CRITICAL|HIGH|MEDIUM|LOW|INFO>
Category: <IDOR|XSS|SSRF|Auth Bypass|Info Disclosure|Misconfiguration|Open Redirect|Business Logic|Subdomain Takeover|API Security|Other>
Description: <what was found>
Evidence: <the specific data/URL/header that proves it>
Impact: <what an attacker could do>
Next Steps: <manual test to confirm>
---END---

If no security findings exist in this chunk, output: NO_FINDINGS

Analysis chunk:
```
{chunk}
```"""

CONSOLIDATE_PROMPT = """You are writing a professional HackerOne bug bounty report for {domain}.

Below are ALL extracted security findings from passive reconnaissance.
Create a FINAL REPORT in Markdown format following HackerOne standards.

Requirements:
1. Deduplicate findings (merge similar ones)
2. Sort by severity (CRITICAL → INFO)
3. For each unique finding, include:
   - Title
   - Severity & CVSS estimate
   - Description
   - Steps to Reproduce (based on evidence)
   - Impact
   - Remediation recommendation
4. Add an Executive Summary at the top
5. Add a Methodology section
6. Add a Scope section referencing the HackerOne DoorDash program
7. Note that ALL testing was PASSIVE ONLY (no active scanning per program rules)

Findings to consolidate:
```
{findings}
```"""


def extract_findings_from_analyses(analyses: list[dict]) -> list[str]:
    """Send each analysis through LLM to extract structured findings."""
    all_findings = []

    for analysis in analyses:
        print(f"\n  📋 Extracting findings from: {analysis['source_file']}")
        chunks = chunk_text(analysis["content"], chunk_size=2500)

        for chunk in chunks:
            print(f"     Chunk {chunk['index']+1}/{len(chunks)}...", end="", flush=True)

            prompt = EXTRACT_PROMPT.format(
                domain=TARGET_DOMAIN,
                chunk=chunk["text"],
            )
            result = query_llm(prompt)

            if result["success"] and result["response"]:
                response = result["response"]
                if "NO_FINDINGS" not in response:
                    all_findings.append(response)
                    # Count findings in this chunk
                    count = response.count("---FINDING---")
                    print(f" ✓ {count} findings ({result['duration_s']}s)")
                else:
                    print(f" ✓ no findings ({result['duration_s']}s)")
            else:
                print(f" ✗ {result.get('error', 'failed')}")

            time.sleep(1)

    return all_findings


# ─────────────────────────────────────────────────────────────
#  Phase 3: Consolidate into final report
# ─────────────────────────────────────────────────────────────

def generate_final_report(findings: list[str]) -> str:
    """Consolidate all findings into a final report via LLM."""
    if not findings:
        return generate_no_findings_report()

    # Combine all findings
    all_findings_text = "\n\n".join(findings)

    # If findings are too large, chunk the consolidation too
    if len(all_findings_text) > 3000:
        print("\n  📊 Findings too large for single pass, chunking consolidation...")
        chunks = chunk_text(all_findings_text, chunk_size=2500)
        partial_reports = []

        for chunk in chunks:
            print(f"     Consolidation chunk {chunk['index']+1}/{len(chunks)}...", end="", flush=True)
            prompt = CONSOLIDATE_PROMPT.format(
                domain=TARGET_DOMAIN,
                findings=chunk["text"],
            )
            result = query_llm(prompt)
            if result["success"]:
                partial_reports.append(result["response"])
                print(f" ✓ ({result['duration_s']}s)")
            else:
                print(f" ✗")
            time.sleep(1)

        # Final merge pass
        print("\n  🔗 Final merge pass...", end="", flush=True)
        merge_prompt = f"""Merge these partial bug bounty reports into ONE final coherent report.
Remove duplicates, keep the best description of each finding, maintain severity ordering.
Output clean Markdown.

Partial reports:
```
{"---SECTION---".join(partial_reports)}
```"""
        result = query_llm(merge_prompt)
        if result["success"]:
            print(f" ✓ ({result['duration_s']}s)")
            return result["response"]
        else:
            # Fallback: just concatenate
            return "\n\n".join(partial_reports)
    else:
        # Single pass consolidation
        print("\n  📊 Generating final report...", end="", flush=True)
        prompt = CONSOLIDATE_PROMPT.format(
            domain=TARGET_DOMAIN,
            findings=all_findings_text,
        )
        result = query_llm(prompt)
        if result["success"]:
            print(f" ✓ ({result['duration_s']}s)")
            return result["response"]
        else:
            print(f" ✗ Falling back to raw findings")
            return f"# Bug Bounty Report - {TARGET_DOMAIN}\n\n## Raw Findings\n\n{all_findings_text}"


def generate_no_findings_report() -> str:
    """Generate a report when no findings were extracted."""
    return f"""# Bug Bounty Passive Reconnaissance Report
## Target: {TARGET_DOMAIN}
## Program: HackerOne - DoorDash
## Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}

---

## Executive Summary

Passive reconnaissance was conducted on {TARGET_DOMAIN} as part of the
HackerOne DoorDash bug bounty program. All testing was limited to
**passive techniques only** in compliance with program rules that
prohibit automated security scanners.

## Methodology

- Subdomain enumeration (subfinder, passive sources)
- Historical URL discovery (gau, waybackurls)
- DNS resolution analysis
- HTTP header/technology detection
- JavaScript file analysis
- Parameter discovery
- Security header audit

## Findings

No critical or high-severity findings were identified through passive
reconnaissance alone. Further **manual testing** is recommended on the
interesting endpoints and parameters identified during recon.

## Recommendations

1. Conduct manual testing on identified API endpoints
2. Review JavaScript files for hardcoded secrets
3. Test discovered parameters for injection vulnerabilities
4. Verify authentication on discovered admin/internal endpoints

## Data Files

Recon data is available in: `{TARGET_DIR}`
LLM analysis is available in: `{TARGET_LLM_DIR}`
"""


# ─────────────────────────────────────────────────────────────
#  Report Output
# ─────────────────────────────────────────────────────────────

def save_report(report_md: str, findings: list[str], fmt: str = "markdown"):
    """Save the final report in requested format."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"bbhunter_report_{TARGET_DOMAIN.replace('.', '_')}_{timestamp}"

    # Always save Markdown
    md_file = TARGET_REPORT_DIR / f"{base_name}.md"

    # Add metadata header
    full_report = f"""<!-- BBHunter Report -->
<!-- Target: {TARGET_DOMAIN} -->
<!-- Date: {datetime.now(timezone.utc).isoformat()} -->
<!-- LLM: {LLM_MODEL} -->
<!-- Mode: PASSIVE RECON ONLY -->

{report_md}

---

*Report generated by BBHunter Automation Suite*
*LLM: {LLM_MODEL}*
*Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*
*Mode: Passive reconnaissance only — no automated scanners used*
"""
    md_file.write_text(full_report)
    print(f"\n  📝 Markdown report: {md_file}")

    # Save raw findings JSON
    json_file = TARGET_REPORT_DIR / f"{base_name}_findings.json"
    json_data = {
        "target": TARGET_DOMAIN,
        "program": "HackerOne - DoorDash",
        "date": datetime.now(timezone.utc).isoformat(),
        "llm_model": LLM_MODEL,
        "methodology": "passive_recon_only",
        "raw_findings_count": len(findings),
        "raw_findings": findings,
        "report_file": md_file.name,
    }
    json_file.write_text(json.dumps(json_data, indent=2))
    print(f"  📋 Findings JSON: {json_file}")

    # ── Store report + findings in DB ──
    if _db and _target_id:
        try:
            from db_manager import parse_llm_findings
            # Parse structured vulns from all finding blocks
            vuln_count = 0
            for finding_text in findings:
                parsed = parse_llm_findings(finding_text)
                for v in parsed:
                    v["source"] = "report_extraction"
                vuln_count += _db.store_vulnerabilities(
                    _target_id, _scan_run_id, parsed)
            _db.log_action("report_saved", TARGET_DOMAIN,
                           details={"file": str(md_file), "vulns_stored": vuln_count},
                           scan_run_id=_scan_run_id)
            print(f"  💾 {vuln_count} structured findings → DB")

            # Store DB stats
            stats = _db.get_stats(_target_id)
            print(f"  📊 DB totals: {stats.get('vulnerabilities',0)} vulns | "
                  f"{stats.get('llm_chunks',0)} chunks | "
                  f"{stats.get('assets',0)} assets")
        except Exception as e:
            print(f"  ⚠️  DB store error: {e}")

    # HTML conversion if requested
    if fmt == "html":
        try:
            import markdown
            html_content = markdown.markdown(report_md, extensions=["tables", "fenced_code"])
            html_file = TARGET_REPORT_DIR / f"{base_name}.html"
            html_template = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>BBHunter Report - {TARGET_DOMAIN}</title>
<style>
body {{ font-family: -apple-system, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #333; }}
h1 {{ color: #d32f2f; border-bottom: 2px solid #d32f2f; }}
h2 {{ color: #1565c0; }}
h3 {{ color: #2e7d32; }}
code {{ background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }}
pre {{ background: #263238; color: #aed581; padding: 16px; border-radius: 8px; overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #1565c0; color: white; }}
.critical {{ color: #d32f2f; font-weight: bold; }}
.high {{ color: #f57c00; font-weight: bold; }}
.medium {{ color: #fbc02d; font-weight: bold; }}
.low {{ color: #388e3c; }}
</style>
</head><body>{html_content}</body></html>"""
            html_file.write_text(html_template)
            print(f"  🌐 HTML report: {html_file}")
        except ImportError:
            print("  ⚠️  Install 'markdown' package for HTML output: pip install markdown")

    return md_file


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="BBHunter LLM Report Generator")
    parser.add_argument("--format", choices=["markdown", "html"], default="markdown")
    parser.add_argument("--skip-extraction", action="store_true",
                        help="Use raw analyses directly without re-extracting findings")
    args = parser.parse_args()

    ensure_dirs()

    print(f"\n╔{'═'*58}╗")
    print(f"║  BBHunter LLM Report Generator                           ║")
    print(f"╠{'═'*58}╣")
    print(f"║  Target: {TARGET_DOMAIN:<48}║")
    print(f"║  LLM: {LLM_MODEL:<51}║")
    print(f"║  Output: {str(TARGET_REPORT_DIR)[-48:]:<48}║")
    print(f"╚{'═'*58}╝\n")

    # Check LLM
    print("Checking LLM...")
    if not check_llm_health():
        print("\n⚠️  Start Ollama: ollama serve")
        sys.exit(1)

    # ── Initialize DB ──
    init_report_db()

    # Collect analyses
    print("\n📁 Collecting LLM analyses...")
    analyses = collect_analyses()

    if not analyses:
        print("No analyses found. Run llm_analyzer.py first.")
        sys.exit(1)

    print(f"   Found {len(analyses)} analysis files:")
    for a in analyses:
        print(f"     {a['source_file']}: {a['size']:,} chars")

    # Phase 2: Extract findings
    if args.skip_extraction:
        print("\n⏭  Skipping extraction, using raw analyses")
        findings = [a["content"] for a in analyses]
    else:
        print("\n🔍 Phase 2: Extracting structured findings...")
        findings = extract_findings_from_analyses(analyses)

    print(f"\n   Total finding blocks: {len(findings)}")

    # Phase 3: Generate consolidated report
    print("\n📊 Phase 3: Generating consolidated report...")
    report = generate_final_report(findings)

    # Save
    print("\n💾 Saving report...")
    report_file = save_report(report, findings, fmt=args.format)

    print(f"\n\n{'='*60}")
    print(f"✅ Report generation complete!")
    print(f"   📝 Report: {report_file}")
    print(f"   📁 All outputs: {TARGET_REPORT_DIR}")


if __name__ == "__main__":
    main()

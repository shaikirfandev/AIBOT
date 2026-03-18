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
    DOORDASH_RULES, ensure_dirs, PROGRAM_NAME,
)
from llm_analyzer import query_llm, chunk_text, check_llm_health

# ── DB integration ──
_db = None
_target_id = ""
_scan_id = ""

def init_report_db():
    """Initialize DB for report generation."""
    global _db, _target_id, _scan_id
    try:
        from db_manager import get_db
        _db = get_db()
        _target_id = _db.get_target_id(TARGET_DOMAIN)
        if not _target_id:
            _target_id = _db.upsert_target(TARGET_DOMAIN)
        _scan_id = _db.start_scan(_target_id, "report_generation")
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

EXTRACT_PROMPT = """You are an expert bug bounty triage analyst extracting structured findings.

Below is a chunk of LLM analysis output from passive reconnaissance on {domain}.
Your job: extract EVERY security-relevant finding into a strict structured format.

## Extraction Rules:
1. One finding = one distinct vulnerability or security issue
2. Merge closely related sub-findings into one finding
3. Assign confidence based on evidence strength
4. Estimate CVSS 3.1 base score for each finding
5. Identify which findings can chain together

For each finding, output EXACTLY this format:
---FINDING---
Title: <concise, specific title -- include affected asset>
Severity: <CRITICAL|HIGH|MEDIUM|LOW|INFO>
CVSS: <X.X -- estimate CVSS 3.1 base score>
Confidence: <CONFIRMED|LIKELY|POSSIBLE|SPECULATIVE>
Category: <IDOR|XSS|SSRF|SQLi|Auth Bypass|Info Disclosure|Misconfiguration|Open Redirect|Business Logic|Subdomain Takeover|API Security|CORS|CSRF|JWT Issues|Cloud Misconfig|Path Traversal|Command Injection|Other>
Asset: <the specific URL/subdomain/endpoint>
Description: <what was found -- be specific>
Evidence: <the exact data/URL/header proving it -- copy from the analysis>
Impact: <realistic attack scenario -- what could an attacker achieve?>
Chain: <can this combine with other findings? which ones and how?>
Next Steps: <specific manual test commands (curl/burp/browser) to confirm>
---END---

If NO security findings exist in this chunk, output: NO_FINDINGS

Analysis chunk:
```
{chunk}
```"""

CONSOLIDATE_PROMPT = """You are writing a professional HackerOne bug bounty report for {domain}.

Below are ALL extracted security findings from passive reconnaissance.
Create a FINAL REPORT in Markdown format following HackerOne professional standards.

## Report Structure (follow this exactly):

### 1. Executive Summary
- Total findings by severity (table: Critical/High/Medium/Low/Info with counts)
- Top 3 most impactful findings (one sentence each)
- Overall security posture assessment (1 paragraph)

### 2. Scope & Methodology
- Target: {domain} (HackerOne program)
- WARNING: ALL testing was PASSIVE ONLY (no active scanning per program rules)
- Tools used: subfinder, amass, gau, waybackurls, httpx, katana, hakrawler, dnsx
- Analysis: AI-assisted with manual validation

### 3. Findings (sorted by CVSS score descending)
For EACH unique finding:

#### [SEVERITY] Finding Title
| Field | Value |
|-------|-------|
| CVSS Score | X.X |
| Category | ... |
| Affected Asset | exact URL/endpoint |
| Confidence | CONFIRMED/LIKELY/POSSIBLE |

**Description:** What was found and why it matters

**Evidence:**
```
<exact evidence from recon data>
```

**Impact:** Realistic attack scenario

**Steps to Reproduce:**
1. Step-by-step instructions
2. Include curl commands where possible

**Attack Chain Potential:** How this combines with other findings

**Remediation:**
- Specific fix recommendation
- Industry standard reference (OWASP, CWE)

### 4. Attack Chain Analysis
- Map connected findings into exploitation paths
- Show: Finding A -> Finding B -> Impact
- Prioritize chains by combined CVSS impact

### 5. Recommendations (Priority Order)
- Immediate (Critical/High findings)
- Short-term (Medium findings)
- Long-term (Hardening)

## Deduplication Rules:
- Merge findings with identical root causes
- Keep the most detailed description
- Combine evidence from all instances
- Use highest severity among duplicates
- List all affected assets under one finding

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
## Program: {PROGRAM_NAME}
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
*Mode: Passive reconnaissance only -- no automated scanners used*
"""
    md_file.write_text(full_report)
    print(f"\n  📝 Markdown report: {md_file}")

    # Save raw findings JSON
    json_file = TARGET_REPORT_DIR / f"{base_name}_findings.json"
    json_data = {
        "target": TARGET_DOMAIN,
        "program": PROGRAM_NAME,
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
                    _target_id, _scan_id, parsed)
            _db.log_action("report_saved", TARGET_DOMAIN,
                           details={"file": str(md_file), "vulns_stored": vuln_count},
                           scan_id=_scan_id)
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
            # Build HTML template without f-string to avoid CSS/f-string conflicts
            css = (
                "body { font-family: -apple-system, sans-serif; max-width: 900px;"
                " margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #333; }\n"
                "h1 { color: #d32f2f; border-bottom: 2px solid #d32f2f; }\n"
                "h2 { color: #1565c0; }\n"
                "h3 { color: #2e7d32; }\n"
                "code { background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }\n"
                "pre { background: #263238; color: #aed581; padding: 16px;"
                " border-radius: 8px; overflow-x: auto; }\n"
                "table { border-collapse: collapse; width: 100%; }\n"
                "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n"
                "th { background: #1565c0; color: white; }\n"
                ".critical { color: #d32f2f; font-weight: bold; }\n"
                ".high { color: #f57c00; font-weight: bold; }\n"
                ".medium { color: #fbc02d; font-weight: bold; }\n"
                ".low { color: #388e3c; }"
            )
            html_template = (
                "<!DOCTYPE html>\n<html><head>\n"
                '<meta charset="utf-8">\n'
                f"<title>BBHunter Report - {TARGET_DOMAIN}</title>\n"
                f"<style>\n{css}\n</style>\n"
                f"</head><body>{html_content}</body></html>"
            )
            html_file.write_text(html_template)
            print(f"  HTML report: {html_file}")
        except ImportError:
            print("  Install 'markdown' package for HTML output: pip install markdown")

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

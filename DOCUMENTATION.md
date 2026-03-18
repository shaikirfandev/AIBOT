# BBHunter Documentation

> **Bug Bounty Automation Suite** — Passive recon, LLM-powered analysis, ML-enhanced vulnerability scanning, and professional report generation.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites & Installation](#3-prerequisites--installation)
4. [Configuration](#4-configuration)
5. [Quick Start](#5-quick-start)
6. [Usage Reference](#6-usage-reference)
7. [Execution Flow](#7-execution-flow)
8. [Engine Reference](#8-engine-reference)
9. [Scanner Modules](#9-scanner-modules)
10. [Data Flow & Storage](#10-data-flow--storage)
11. [LLM Analysis Pipeline](#11-llm-analysis-pipeline)
12. [Report Generation](#12-report-generation)
13. [Dashboard API](#13-dashboard-api)
14. [Docker Deployment](#14-docker-deployment)
15. [Safety & Scope Enforcement](#15-safety--scope-enforcement)
16. [Intelligence Features (v2)](#16-intelligence-features-v2)
17. [Timeout & Skip Control](#17-timeout--skip-control)
18. [Directory Structure](#18-directory-structure)
19. [Troubleshooting](#19-troubleshooting)

---

## 1. Project Overview

BBHunter is a modular bug bounty automation suite designed for **passive-first reconnaissance** and **intelligent vulnerability analysis**. It combines:

- **14-step passive recon pipeline** using Go-based OSINT tools
- **Chunk-based LLM analysis** via Ollama (dolphin-llama3:8b) with a 3-pass methodology
- **7 async engines** for surface mapping, scanning, analysis, payload generation, assistant suggestions, reporting, and machine learning
- **10 vulnerability scanner modules** with context-aware detection
- **ML-powered false positive reduction** using GradientBoosting + RandomForest
- **Professional report generation** in HackerOne format with CVSS 3.1 scoring

The current target is the **DoorDash HackerOne** bug bounty program, operating in **passive-only mode** (no automated active scanning per program rules).

---

## 2. Architecture

BBHunter uses a **dual-layer architecture**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ENTRY POINTS                             │
│  run.sh  │  bbhunter CLI  │  Dashboard API  │  run_pipeline.py  │
└─────┬────┴───────┬─────────┴────────┬────────┴──────┬───────────┘
      │            │                  │               │
      ▼            ▼                  ▼               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    SCRIPTS LAYER (sync)                         │
│  hunt.py ─── llm_analyzer.py ─── engine_bridge.py ─── gen_report│
│       │              │                  │                       │
│  db_manager.py    config.py      (asyncio.run)                  │
└──────┬───────────────┬──────────────────┬───────────────────────┘
       │               │                  │
       ▼               ▼                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                   BBHUNTER LAYER (async)                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐          │
│  │  Recon   │ │ Surface  │ │ Scanner  │ │ Analysis  │          │
│  │  Engine  │ │ Mapping  │ │ (10 mods)│ │ Engine v2 │          │
│  └──────────┘ └──────────┘ └──────────┘ └───────────┘          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐          │
│  │ Payloads │ │Assistant │ │Reporting │ │ Learning  │          │
│  │Engine v2 │ │Engine v2 │ │  Engine  │ │ Engine v2 │          │
│  └──────────┘ └──────────┘ └──────────┘ └───────────┘          │
│                                                                 │
│  models.py ─── config.py ─── safety.py ─── database.py         │
└─────────────────────────────────────────────────────────────────┘
       │                            │
       ▼                            ▼
┌──────────────┐           ┌──────────────┐
│  SQLite DB   │           │  Ollama LLM  │
│ (aiosqlite)  │           │ dolphin-llama│
└──────────────┘           └──────────────┘
```

### Layer Descriptions

| Layer | Location | Runtime | Purpose |
|-------|----------|---------|---------|
| **Scripts** | `scripts/` | Synchronous Python | Pipeline orchestration, Go tool execution, LLM chunk analysis, report generation |
| **BBHunter** | `bbhunter/` | Async (asyncio) | Engine library with Pydantic models, async scanners, ML analysis, payload generation |
| **Bridge** | `scripts/engine_bridge.py` | Hybrid | Connects scripts layer to bbhunter engines via `asyncio.run()` |

---

## 3. Prerequisites & Installation

### System Requirements

- **Python 3.11+** (tested on 3.14)
- **Go 1.21+** (for recon tools)
- **Ollama** with `dolphin-llama3:8b` model
- **macOS or Linux** (Docker available for cross-platform)

### Python Dependencies

Defined in `pyproject.toml`:

```
httpx          – async HTTP client
pydantic       – data validation & models
fastapi        – dashboard REST API
uvicorn        – ASGI server
click          – CLI framework
rich           – terminal UI (progress bars, tables, panels)
scikit-learn   – ML models (false positive detection)
numpy          – numerical operations
celery         – task queue (background jobs)
redis          – Celery broker
aiosqlite      – async SQLite driver
beautifulsoup4 – HTML parsing
pyyaml         – YAML config parsing
jinja2         – report templating
```

### Go Recon Tools

Installed to `~/go/bin/` via `install_tools.sh`:

| Tool | Purpose |
|------|---------|
| `subfinder` | Passive subdomain enumeration |
| `amass` | Advanced subdomain discovery (passive) |
| `httpx` | HTTP probing & technology detection |
| `dnsx` | DNS resolution & record queries |
| `gau` | Get All URLs from archives |
| `waybackurls` | Wayback Machine URL extraction |
| `katana` | Web crawler for URL discovery |
| `hakrawler` | Fast web crawler |
| `nuclei` | Template-based vulnerability scanner |

### Installation Steps

```bash
# 1. Clone and enter the project
cd /path/to/superbot

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -e .

# 4. Install Go recon tools
chmod +x install_tools.sh
./install_tools.sh

# 5. Install and start Ollama
brew install ollama          # macOS
ollama serve &               # start Ollama daemon
ollama pull dolphin-llama3:8b   # download model

# 6. Verify installation
./run.sh check
```

---

## 4. Configuration

### 4.1 Main Config: `config.yaml`

The master configuration file with all tunables. Key sections:

```yaml
app:
  name: "BBHunter"
  version: "1.0.0"
  debug: false

safety:
  require_authorization: true
  allowed_targets_file: "authorized_targets.yaml"
  rate_limit_per_second: 5

database:
  url: "sqlite+aiosqlite:///data/bbhunter.db"

llm:
  provider: "ollama"
  model: "dolphin-llama3:8b"
  base_url: "http://localhost:11434"
  max_tokens: 4096
  temperature: 0.3
  timeout: 120

scanner:
  categories:                    # 14 vuln categories
    - xss
    - sqli
    - ssrf
    - idor
    - cors
    - open_redirect
    - ssti
    - header_security
    - jwt
    - auth_bypass
    - csrf
    - xxe
    - rce
    - info_disclosure
  max_concurrent_scans: 5
  request_timeout: 30
  passive_only: true             # DoorDash rule enforcement

target_rules:
  doordash:
    no_automated_scanners: true
    in_scope:
      - "www.doordash.com"
      - "doordash.com"
    out_of_scope_domains:
      - "driver.doordash.com"
      - "merchant.doordash.com"
      # ... 7 more
    out_of_scope_paths:
      - "/auth/*"
      - "/api/v1/auth/*"
      - "/logout"
```

### 4.2 Target Authorization: `authorized_targets.yaml`

Defines which targets are authorized for testing:

```yaml
targets:
  - domain: "doordash.com"
    program: "hackerone"
    authorized: true
    scope:
      include:
        - "*.doordash.com"
      exclude:
        - "driver.doordash.com"
        - "merchant.doordash.com"
        - "*.doordashstatic.com"
```

Every operation passes through `SafetyGate.check(domain)` — unauthorized targets are rejected.

### 4.3 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BB_TARGET` | `doordash.com` | Target domain for the pipeline |
| `BB_CONFIG` | `config.yaml` | Path to main config file |
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama API endpoint |
| `BB_STEP_TIMEOUT` | `600` | Max seconds per recon tool step (0=no limit) |
| `BB_CHUNK_TIMEOUT` | `300` | Max seconds per LLM chunk request (0=use llm.request_timeout) |
| `BB_MAX_FAILURES` | `3` | Skip to next file/step after N consecutive LLM failures |

---

## 5. Quick Start

### One-Command Full Pipeline

```bash
./run.sh all
```

This runs the complete pipeline: recon → LLM analysis → engine processing → report generation.

### Step-by-Step Execution

```bash
# Step 1: Passive reconnaissance (14 steps)
./run.sh recon

# Step 2: LLM-powered analysis of recon data
./run.sh analyze

# Step 3: Generate final report
./run.sh report

# Resume from where you left off (uses checkpoint)
./run.sh resume
```

### Change Target

```bash
./run.sh target example.com
# or
export BB_TARGET=example.com
./run.sh all
```

### Check Prerequisites

```bash
./run.sh check
```

---

## 6. Usage Reference

### 6.1 Shell Entry Point: `run.sh`

```
Usage: ./run.sh {recon|analyze|report|resume|target <domain>|check|all}

Commands:
  recon              Run Phase 1: 14-step passive reconnaissance
  analyze            Run Phase 2: LLM chunk analysis of recon data
  report             Run Phase 3: Generate markdown report
  resume             Resume pipeline from last checkpoint
  target <domain>    Run full pipeline against a specific domain
  check              Verify all prerequisites are installed
  all                Run the complete pipeline (default)
```

### 6.2 CLI: `bbhunter`

The `bbhunter` command is registered via `pyproject.toml` as a Click CLI:

```
Usage: bbhunter [COMMAND] [OPTIONS]

Commands:
  recon       Run reconnaissance on a domain
  surface     Map attack surface for a domain
  scan        Scan endpoints for vulnerabilities
  full        Run complete pipeline: recon → surface → scan → analysis → report
  report      Generate a report for a completed scan
  payloads    Generate payloads for a vulnerability category
  dashboard   Launch the web dashboard
  decode      Decode data (base64, JWT, URL-encoded, hex)
  learning    Learning module commands (stats, retrain)
  tools       External tool management and execution
```

#### Key CLI Commands

**Reconnaissance:**
```bash
bbhunter recon example.com
bbhunter recon example.com -o results.json
```

**Surface Mapping:**
```bash
bbhunter surface example.com
```

**Vulnerability Scanning:**
```bash
bbhunter scan example.com
bbhunter scan example.com --scanners xss,sqli,ssrf
```

**Full Pipeline:**
```bash
bbhunter full example.com
bbhunter full example.com -o full_results.json
```

**Payload Generation:**
```bash
bbhunter payloads xss --context html --waf cloudflare --mutate
bbhunter payloads sqli --context url
bbhunter payloads ssrf
bbhunter payloads ssti
```

**Dashboard:**
```bash
bbhunter dashboard                    # starts on http://127.0.0.1:8000
bbhunter dashboard --port 9000
```

**Learning Module:**
```bash
bbhunter learning stats               # show ML model statistics
bbhunter learning retrain             # retrain from all feedback data
```

**External Tools:**
```bash
bbhunter tools status                 # show installed tools
bbhunter tools run subfinder example.com -o subs.json
bbhunter tools recon-all example.com  # run all recon tools
bbhunter tools scan-nuclei https://example.com -s critical,high
bbhunter tools scan-sqlmap "https://example.com/page?id=1" -l 3
bbhunter tools fuzz https://example.com/FUZZ -w wordlist.txt
```

**Data Decoding:**
```bash
bbhunter decode "eyJhbGciOiJIUzI1NiJ9..."   # auto-detects JWT, base64, hex, URL
```

### 6.3 Pipeline Script: `scripts/run_pipeline.py`

```
Usage: python3 scripts/run_pipeline.py [OPTIONS]

Options:
  --target DOMAIN     Target domain (default: BB_TARGET env var)
  --phase PHASE       Run specific phase: recon, analyze, engines, report
  --resume            Resume from last checkpoint
  --format FORMAT     Report format: markdown, html, json
  --check             Check prerequisites only
  --skip-engines      Skip the engine processing phase
  --step-timeout N    Max seconds per recon tool step (0=use config default)
  --chunk-timeout N   Max seconds per LLM chunk request (0=use config default)
  --max-failures N    Skip to next file after N consecutive LLM failures
```

### 6.4 Engine Bridge: `scripts/engine_bridge.py`

```
Usage: python3 scripts/engine_bridge.py [OPTIONS]

Options:
  --engine NAME       Run a single engine: surface, scanner, analysis,
                      payloads, assistant, reporting, learning
  --engines LIST      Comma-separated list of engines to run
  --list              List all available engines
  --skip-surface      Skip surface mapping (use existing data)
```

---

## 7. Execution Flow

### 7.1 Full Pipeline: `./run.sh all`

When you run `./run.sh all`, here is the complete execution flow:

```
./run.sh all
  │
  ├─ Activates Python venv
  ├─ Sets PATH for Go tools (~go/bin)
  ├─ Exports BB_TARGET (default: doordash.com)
  │
  └─ python3 scripts/run_pipeline.py
       │
       ├─ PHASE 0: Prerequisites Check
       │   ├─ Validates Go tools: subfinder, amass, httpx, dnsx, gau, etc.
       │   ├─ Checks Ollama is running + model available
       │   ├─ Verifies Python dependencies
       │   └─ Confirms target is authorized via SafetyGate
       │
       ├─ PHASE 1: Reconnaissance  →  scripts/hunt.py
       │   ├─ Step  1: Subdomain enumeration (subfinder)
       │   ├─ Step  2: Amass passive enum
       │   ├─ Step  3: DNS resolution (dnsx)
       │   ├─ Step  4: HTTP probing (httpx)
       │   ├─ Step  5: URL discovery (gau)
       │   ├─ Step  6: Wayback URLs
       │   ├─ Step  7: Katana crawl
       │   ├─ Step  8: Hakrawler crawl
       │   ├─ Step  9: Technology detection (httpx -tech-detect)
       │   ├─ Step 10: Passive port scan (Shodan/Censys data)
       │   ├─ Step 11: JavaScript file analysis
       │   ├─ Step 12: Parameter discovery
       │   ├─ Step 13: Security header analysis (httpx)
       │   └─ Step 14: Scope filtering (removes out-of-scope results)
       │   Output: data/<target>/01_subdomains_inscope.txt
       │           data/<target>/02_dns_resolved.txt
       │           data/<target>/02b_httpx_live.txt
       │           data/<target>/03_urls_interesting.txt
       │           ... (14 numbered output files)
       │
       ├─ PHASE 2: LLM Analysis  →  scripts/llm_analyzer.py
       │   ├─ Reads each recon output file
       │   ├─ Splits into chunks (~3000 chars with overlap)
       │   ├─ Sends each chunk to Ollama with 3-pass analysis prompt:
       │   │   Pass 1: Discovery (inventory assets, highlight anomalies)
       │   │   Pass 2: Validation (cross-reference, check consistency)
       │   │   Pass 3: Attack Chains (build exploitation scenarios)
       │   ├─ Stores chunk results in SQLite
       │   ├─ Merges chunk analyses into per-file summaries
       │   └─ Saves to llm_analysis/<target>/<step>/_merged_analysis.txt
       │
       ├─ PHASE 3: Engine Processing  →  scripts/engine_bridge.py
       │   ├─ Loads recon data from files into Pydantic models
       │   ├─ Runs 7 engines in sequence:
       │   │   1. Surface Mapping Engine
       │   │   2. Vulnerability Scanner (10 modules, passive-only)
       │   │   3. Analysis Engine v2 (CVSS scoring, ML FP reduction)
       │   │   4. Payload Engine v2 (WAF-aware generation)
       │   │   5. Manual Testing Assistant v2 (tech playbooks)
       │   │   6. Reporting Engine (structured output)
       │   │   7. Learning Engine v2 (model training + trend analysis)
       │   ├─ Stores results in SQLite
       │   └─ Writes to data/<target>/engines/
       │
       └─ PHASE 4: Report Generation  →  scripts/generate_report.py
            ├─ Collects all merged LLM analyses
            ├─ Phase 1: Extract structured findings (CVSS, confidence, categories)
            ├─ Phase 2: Consolidate into professional report
            ├─ Phase 3: Output in HackerOne format
            └─ Saves to reports/<target>/
                 ├─ final_report.md
                 ├─ findings.json
                 └─ report.html (optional)
```

### 7.2 Pipeline State & Resume

Pipeline state is saved to `data/pipeline_state.json` after each phase:

```json
{
  "target": "doordash.com",
  "current_phase": "analyze",
  "completed_phases": ["recon"],
  "started_at": "2024-01-15T10:30:00",
  "last_updated": "2024-01-15T11:45:00"
}
```

Running `./run.sh resume` picks up from the last completed phase.

### 7.3 CLI Full Pipeline: `bbhunter full`

The CLI's `full` command runs a different (lighter) path through the bbhunter engine layer directly:

```
bbhunter full example.com
  │
  ├─ Safety gate check
  ├─ Phase 1: ReconEngine.run(domain)
  ├─ Phase 2: SurfaceMappingEngine.run(domain, subdomains)
  ├─ Phase 3: VulnerabilityScanner.run(domain, endpoints)
  ├─ Phase 4: AnalysisEngine.run(vulnerabilities)
  └─ Phase 5: ReportEngine.generate_all_reports(...)
```

This bypasses the scripts layer entirely and runs the async engines directly.

---

## 8. Engine Reference

### 8.1 Recon Engine (`bbhunter/engines/recon/`)

Orchestrates multiple recon modules:

| Module | File | Purpose |
|--------|------|---------|
| Subdomain Discovery | `subdomain.py` | Subfinder + Amass integration |
| DNS Enumeration | `dns_enum.py` | DNS record resolution via dnsx |
| CT Logs | `ct_logs.py` | Certificate Transparency monitoring |
| ASN Lookup | `asn_lookup.py` | ASN and IP range discovery |
| Wayback | `wayback.py` | Wayback Machine URL extraction |
| Cloud Recon | `cloud_recon.py` | Cloud asset fingerprinting (S3, Azure, GCP) |
| GitHub Recon | `github_recon.py` | GitHub dork scanning |
| Reverse IP | `reverse_ip.py` | Reverse IP lookups for shared hosting |

### 8.2 Surface Mapping Engine (`bbhunter/engines/surface/`)

Maps the complete attack surface from recon data:
- Endpoint enumeration and classification
- Technology fingerprinting
- WAF detection
- API endpoint identification
- Input parameter mapping

### 8.3 Vulnerability Scanner (`bbhunter/engines/scanner/`)

Orchestrates 10 specialized scanner modules. See [Scanner Modules](#9-scanner-modules) for details.

Key features:
- Engine injection: `set_payload_engine()` and `set_learning_engine()` propagate to all child scanners
- Scanner selection via `scanners` parameter
- Passive-only mode enforcement for restricted targets
- Concurrent scanning with configurable limits

### 8.4 Analysis Engine v2 (`bbhunter/engines/analysis/`)

**706 lines** of intelligence:

- **CVSS 3.1 Estimation**: Automated scoring based on vulnerability characteristics
- **ML False Positive Reduction**: GradientBoosting + RandomForest ensemble model
  - 26 features extracted per finding
  - Trained on historical feedback data
  - Confidence scoring with probability calibration
- **Contextual Correlation**: Groups related findings to identify compound attack paths
- **Dynamic Chain Detection**: 17 exploit chain patterns recognized:
  - Stored XSS → Admin takeover
  - SSRF → Cloud metadata → RCE
  - IDOR → Data exfiltration
  - Open redirect → OAuth token theft
  - CORS misconfiguration → Account takeover
  - ... and more
- **Temporal Analysis**: Tracks vulnerability trends over time
- **Impact Assessment**: Business impact scoring with risk matrices

### 8.5 Payload Engine v2 (`bbhunter/engines/payloads/`)

**838 lines** of payload intelligence:

- **WAF Fingerprinting**: Identifies 10 WAF vendors (Cloudflare, AWS WAF, Akamai, Imperva, Sucuri, F5, ModSecurity, Barracuda, Fortinet, Citrix)
- **Response-Adaptive Mutation**: Analyzes WAF response patterns and mutates payloads to bypass
- **Encoding Chains**: Multi-layer encoding (URL → HTML → Unicode → double-encoding)
- **Polyglot Payloads**: Single payloads that work across XSS/SQLi/SSTI contexts
- **Tech-Stack-Aware Selection**: Adapts payloads based on detected technology stack
- **8+ Vulnerability Categories**: XSS, SQLi, SSRF, SSTI, XXE, LFI, RCE, command injection
- **Learning Integration**: Records successful/failed payloads for model improvement

### 8.6 Assistant Engine v2 (`bbhunter/engines/assistant/`)

Manual testing guidance and intelligence:

- **6 Technology Playbooks**: Framework-specific testing guides (React, Angular, Django, Rails, Spring, Node.js)
- **11 URL Attack Maps**: URL-pattern-based vulnerability suggestions
- **10 Parameter Attack Maps**: Parameter-name-based testing recommendations
- **15 Sensitive Pattern Detectors**: Regex-based detection of API keys, tokens, secrets
- **CORS Test Generator**: Builds CORS misconfiguration test cases
- **Business Logic Suggestions**: Context-aware logic flaw testing ideas
- **Data Decoder**: Auto-detects and decodes base64, JWT, URL-encoding, hex

### 8.7 Reporting Engine (`bbhunter/engines/reporting/`)

Generates structured reports:
- Multiple templates: HackerOne, Bugcrowd, Executive
- Markdown, HTML, and JSON output
- CVSS scoring tables
- Attack chain visualization
- Prioritized remediation guidance

### 8.8 Learning Engine v2 (`bbhunter/engines/learning/`)

ML-powered continuous improvement:

- **26-Feature Extraction**: Comprehensive feature engineering from vulnerability data
- **Dual Model Ensemble**: GradientBoosting + RandomForest voting
- **WAF Payload Tracking**: Records which payloads succeed/fail against which WAFs
- **Trend Analysis**: Identifies vulnerability patterns over time
- **Feedback Loop**: Ingests true/false positive feedback to improve accuracy
- **Model Persistence**: Saves trained models to disk for reuse
- **Statistics API**: Exposes model performance metrics

---

## 9. Scanner Modules

All scanners inherit from `BaseScanner` and implement `async scan(target, endpoint)`.

### 9.1 XSS Scanner v2 (`xss_scanner.py`)

Context-aware cross-site scripting detection:

- **5 Injection Contexts**: HTML body, attribute, JavaScript, URL, CSS
- **Canary-First Reflection**: Sends unique canary string, checks if reflected
- **Context Detection**: Analyzes surrounding HTML to determine injection context
- **DOM XSS Analysis**: Detects dangerous source+sink patterns in JavaScript
  - Sources: `document.URL`, `location.hash`, `document.referrer`, `window.name`, `postMessage`
  - Sinks: `innerHTML`, `eval()`, `document.write()`, `setTimeout()`, `Function()`
- **PayloadEngine Integration**: Fetches WAF-aware, context-specific payloads
- **LearningEngine Integration**: Reports results back for model improvement

### 9.2 SQL Injection Scanner (`sqli_scanner.py`)

Three-phase SQL injection detection:

1. **Error-Based** (14 payloads): Triggers SQL error messages, matches against patterns for MySQL, PostgreSQL, MSSQL, Oracle, SQLite
2. **Boolean Blind** (truth/falsehood pairs): `' OR '1'='1` vs `' OR '1'='2`, compares response similarity
3. **Time-Based Blind** (5 payloads): `SLEEP()`, `WAITFOR DELAY`, `pg_sleep()`, measures response time delta

### 9.3 SSRF Scanner (`ssrf_scanner.py`)

Server-side request forgery detection:

- **Cloud Metadata Endpoints**: AWS (169.254.169.254), GCP, Azure
- **Localhost Bypass Techniques**: `127.0.0.1`, `0.0.0.0`, `[::1]`, decimal IP, hex IP
- **DNS Rebinding Patterns**: Detects DNS rebinding-susceptible configurations
- **Protocol Handlers**: `file://`, `gopher://`, `dict://`
- **Parameter Targeting**: Prioritizes URL-like parameter names (`url`, `redirect`, `file`, `path`, `src`)

### 9.4 IDOR Scanner (`idor_scanner.py`)

Insecure Direct Object Reference detection:

- **Parameter ID Manipulation**: Modifies numeric IDs in query parameters
- **URL Path ID Manipulation**: Modifies numeric segments in URL paths
- **Baseline Comparison**: Compares original vs manipulated response to detect access control failure
- **Response Similarity Analysis**: Measures content length deltas and HTTP status differences

### 9.5 CORS Scanner (`cors_scanner.py`)

Cross-Origin Resource Sharing misconfiguration detection:

- Tests with arbitrary origin headers
- Checks `Access-Control-Allow-Origin` reflection
- Validates `Access-Control-Allow-Credentials` exposure
- Tests null origin and subdomain wildcards

### 9.6 Open Redirect Scanner (`open_redirect_scanner.py`)

Unvalidated redirect detection:

- Injects external URLs into redirect parameters
- Detects 3xx redirects to attacker-controlled domains
- Tests common redirect parameter names (`redirect`, `url`, `next`, `return`, `goto`)

### 9.7 SSTI Scanner (`ssti_scanner.py`)

Server-Side Template Injection detection:

- Sends mathematical expressions (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`)
- Checks for computed results in response (e.g., `49`)
- Tests multiple template engines: Jinja2, Twig, Freemarker, Velocity, ERB

### 9.8 Header Scanner (`header_scanner.py`)

Security header analysis:

- Missing header detection: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Weak policy detection (e.g., `unsafe-inline` in CSP)
- Information disclosure in server/powered-by headers

### 9.9 JWT Scanner (`jwt_scanner.py`)

JSON Web Token vulnerability detection:

- Algorithm confusion (none algorithm)
- Weak signing key detection
- Token structure analysis
- Claims validation

### 9.10 Auth Scanner (`auth_scanner.py`)

Authentication bypass detection:

- Default credential testing
- Authentication header manipulation
- Session fixation checks

---

## 10. Data Flow & Storage

### 10.1 File-Based Data Flow

Recon data flows through numbered output files:

```
data/<target>/
  ├── 01_subdomains_inscope.txt     # Filtered subdomains
  ├── 02_dns_resolved.txt           # DNS resolution results
  ├── 02b_httpx_live.txt            # Live HTTP endpoints
  ├── 03_urls_interesting.txt       # Interesting URLs (gau)
  ├── 04_wayback_urls.txt           # Wayback Machine URLs
  ├── 04b_katana_clean.txt          # Katana crawl results
  ├── 04c_hakrawler_clean.txt       # Hakrawler results
  ├── 05_tech_headers.txt           # Technology & headers
  ├── 06_services_passive.txt       # Passive service detection
  ├── 07_js_files.txt               # JavaScript file URLs
  ├── 08_parameters.txt             # Discovered parameters
  ├── 09_security_headers.txt       # Security header audit
  ├── 10_recon_summary.txt          # Aggregate summary
  └── engines/
       ├── analysis_results.txt     # v2 Analysis output
       ├── payloads.txt             # Generated payloads
       ├── attack_vectors.txt       # Attack vector suggestions
       ├── impact_summary.json      # Impact assessment
       └── attack_graph.json        # Exploit chain graph
```

### 10.2 LLM Analysis Output

```
llm_analysis/<target>/
  ├── 01_subdomains_inscope/
  │    ├── chunk_000.json           # Individual chunk analysis
  │    ├── chunk_001.json
  │    └── _merged_analysis.txt     # Combined analysis
  ├── 02_dns_resolved/
  │    ├── chunk_000.json ... chunk_015.json
  │    └── _merged_analysis.txt
  └── ... (one folder per recon output file)
```

### 10.3 SQLite Database

**Dual-layer storage:**

| Layer | Driver | Location | Purpose |
|-------|--------|----------|---------|
| Scripts | `sqlite3` (sync) | `data/bbhunter.db` | Recon results, LLM chunks, pipeline state |
| BBHunter | `aiosqlite` (async) | `data/bbhunter.db` | Engine results, vulnerability records, scan history |

Key tables managed by `scripts/db_manager.py`:
- `recon_results` — raw recon output per step
- `llm_chunks` — individual LLM analysis chunks
- `llm_merged` — merged per-file analyses
- `pipeline_runs` — pipeline execution history

Key tables managed by `bbhunter/database.py`:
- `targets` — registered targets
- `assets` — discovered assets (subdomains, IPs)
- `endpoints` — discovered endpoints
- `vulnerabilities` — found vulnerabilities with CVSS scores
- `scan_results` — scan execution records
- `feedback` — true/false positive feedback for ML

### 10.4 Reports

```
reports/<target>/
  ├── final_report.md          # Main HackerOne-format report
  ├── findings.json            # Structured findings with CVSS
  └── report.html              # HTML version (optional)
```

---

## 11. LLM Analysis Pipeline

### Overview

The LLM analysis pipeline (`scripts/llm_analyzer.py`) processes recon data through Ollama's `dolphin-llama3:8b` model using a **chunk-based approach** designed for low-VRAM systems (4K context window).

### Three-Pass Methodology

Each chunk is analyzed with a system prompt that enforces three passes:

1. **Pass 1 — Discovery**: Inventory all assets, highlight anomalies, flag misconfigurations
2. **Pass 2 — Validation**: Cross-reference data, check for consistency, identify false positives
3. **Pass 3 — Attack Chains**: Build exploitation scenarios, chain vulnerabilities, estimate impact

### File-Type Context Hints

The analysis prompt includes context-specific instructions for 12 recon data types:

| File Pattern | Context Provided |
|---|---|
| `01_subdomains` | Focus on naming patterns, environment indicators (staging/dev/test) |
| `02_dns` | Look for zone transfer potential, internal IPs, CNAMEs to cloud services |
| `02b_httpx` | Analyze HTTP status codes, redirect chains, technology headers |
| `03_urls` | Identify API endpoints, admin panels, file upload paths |
| `04_wayback` / `04b_katana` / `04c_hakrawler` | Look for deprecated endpoints, parameter patterns |
| `05_tech` | Map technology stack, identify version-specific CVEs |
| `07_js` | Look for API keys, tokens, internal endpoints in JS files |
| `08_parameters` | Identify injection points, authentication parameters |
| `09_security_headers` | Evaluate CSP, HSTS, X-Frame-Options policies |
| Default | General security assessment |

### Chunking Strategy

```
Total text ──┬── Chunk 0 (0..3000 chars)
             ├── Chunk 1 (2800..5800 chars)  ← 200-char overlap
             ├── Chunk 2 (5600..8600 chars)
             └── ...
```

- Chunk size: ~3000 characters
- Overlap: ~200 characters (prevents context loss at boundaries)
- Each chunk is sent as a separate Ollama API call
- Results stored per-chunk in JSON files and SQLite

### Resume Capability

Each file being analyzed has a `_state.json` tracking progress:

```json
{
  "file": "01_subdomains_inscope.txt",
  "total_chunks": 5,
  "completed_chunks": 3,
  "last_updated": "2024-01-15T12:00:00"
}
```

Running with `--resume` skips completed chunks.

---

## 12. Report Generation

### Three-Phase Process (`scripts/generate_report.py`)

**Phase 1 — Extract Findings:**
- Reads all merged LLM analyses
- Sends each to Ollama with an extraction prompt requesting structured findings
- Each finding includes: title, severity, CVSS 3.1 score, confidence level, category (17 categories), affected asset, evidence, reproduction steps, chain potential

**Phase 2 — Consolidate:**
- Aggregates all extracted findings
- Sends to Ollama with a consolidation prompt
- Deduplicates findings across recon phases
- Builds attack chain analysis
- If findings exceed context window, uses chunked consolidation with a merge pass

**Phase 3 — Output:**
- Generates final report in HackerOne professional format:
  - Executive Summary
  - CVSS scoring table
  - Detailed findings (ordered by severity)
  - Attack chain analysis with step-by-step walkthroughs
  - Reproduction steps for each finding
  - Prioritized remediation recommendations
  - Appendix with raw evidence
- Outputs: Markdown (always), JSON findings (always), HTML (optional)

### Report Categories (17)

`xss`, `sqli`, `ssrf`, `idor`, `cors`, `open_redirect`, `ssti`, `xxe`, `rce`, `lfi`, `auth_bypass`, `info_disclosure`, `header_security`, `csrf`, `jwt`, `business_logic`, `misconfiguration`

---

## 13. Dashboard API

### Overview

FastAPI-based REST API (`bbhunter/engines/dashboard/api.py`, 743 lines) with real-time WebSocket support.

### Launching

```bash
bbhunter dashboard                     # http://127.0.0.1:8000
bbhunter dashboard --port 9000         # custom port
```

API docs available at `http://127.0.0.1:8000/api/docs` (Swagger UI).

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/targets` | Register a new target |
| `POST` | `/api/recon` | Launch recon (background) |
| `POST` | `/api/surface` | Start surface mapping (background) |
| `POST` | `/api/scan` | Launch vulnerability scan (background) |
| `POST` | `/api/scan/full` | Run full pipeline (background) |
| `GET` | `/api/scans` | List active/completed scans |
| `GET` | `/api/scans/{id}` | Get scan status and results |
| `POST` | `/api/payloads` | Generate payloads |
| `POST` | `/api/feedback` | Submit true/false positive feedback |
| `WS` | `/ws` | Real-time scan status updates |

### WebSocket Events

Connect to `ws://127.0.0.1:8000/ws` for real-time updates:

```json
{
  "event": "phase_change",
  "data": {"scan_id": "full-20240115103000", "phase": "scanning"},
  "timestamp": "2024-01-15T10:35:00"
}
```

Events: `recon_complete`, `surface_complete`, `scan_complete`, `full_scan_complete`, `phase_change`, `recon_error`

### Request Examples

**Start Full Scan:**
```bash
curl -X POST http://127.0.0.1:8000/api/scan/full \
  -H "Content-Type: application/json" \
  -d '{"target_domain": "example.com", "scan_type": "full"}'
```

**Generate Payloads:**
```bash
curl -X POST http://127.0.0.1:8000/api/payloads \
  -H "Content-Type: application/json" \
  -d '{"category": "xss", "context": "html", "waf": "cloudflare"}'
```

**Submit Feedback:**
```bash
curl -X POST http://127.0.0.1:8000/api/feedback \
  -H "Content-Type: application/json" \
  -d '{"vulnerability_id": "vuln-123", "is_true_positive": true, "notes": "Confirmed via manual testing"}'
```

---

## 14. Docker Deployment

### Dockerfile

Based on `python:3.12-slim` with:
- System packages: `git`, `curl`, `dnsutils`, `nmap`
- Non-root user for security
- Go recon tools installed
- Application code copied and installed

### Docker Compose

Three services defined in `docker-compose.yml`:

| Service | Port | Purpose |
|---------|------|---------|
| `bbhunter` | 8000 | Main application + dashboard |
| `redis` | 6379 | Celery message broker |
| `celery-worker` | — | Background task processing |

### Running with Docker

```bash
# Build and start all services
docker-compose up -d

# Run a specific command
docker-compose exec bbhunter ./run.sh recon

# View logs
docker-compose logs -f bbhunter

# Stop all services
docker-compose down
```

### Environment Variables for Docker

Set in `docker-compose.yml` or via `.env` file:

```env
BB_TARGET=doordash.com
OLLAMA_HOST=http://host.docker.internal:11434   # Access host Ollama from container
CELERY_BROKER_URL=redis://redis:6379/0
```

---

## 15. Safety & Scope Enforcement

### Multi-Layer Safety

BBHunter enforces scope at **four levels**:

1. **SafetyGate** (`bbhunter/safety.py`): Validates every domain against `authorized_targets.yaml` before any operation
2. **Scope Filtering** (`scripts/hunt.py`): `filter_in_scope()` removes out-of-scope results after each recon step
3. **Scanner Mode** (`config.yaml`): `passive_only: true` disables active scanning for restricted programs
4. **Target Rules** (`config.yaml`): Per-program rules (DoorDash: no automated scanners, specific in/out-of-scope lists)

### DoorDash-Specific Rules

```yaml
target_rules:
  doordash:
    no_automated_scanners: true     # Only passive analysis allowed
    in_scope:
      - "www.doordash.com"
      - "doordash.com"
    out_of_scope_domains:
      - "driver.doordash.com"
      - "merchant.doordash.com"
      - "dasherdirect.doordash.com"
      - "eng.doordash.com"
      - "blog.doordash.com"
      - "status.doordash.com"
      - "help.doordash.com"
      - "about.doordash.com"
      - "careers.doordash.com"
    out_of_scope_wildcards:
      - "*.doordashstatic.com"
      - "*.doordashcdn.com"
      - "*.doordash-static.com"
    out_of_scope_paths:
      - "/auth/*"
      - "/api/v1/auth/*"
      - "/logout"
```

When `no_automated_scanners: true`, the engine bridge runs the scanner in **passive-only mode**: only header analysis and CORS checks are performed (no active payload injection).

### Authorization Flow

```
User Command → SafetyGate.check(domain) → Load authorized_targets.yaml
                     │
                     ├─ Domain in authorized list? ──No──→ REJECT ❌
                     │
                     ├─ Domain matches scope include? ──No──→ REJECT ❌
                     │
                     ├─ Domain matches scope exclude? ──Yes──→ REJECT ❌
                     │
                     └─ All checks pass → ALLOW ✓
```

---

## 16. Intelligence Features (v2)

### Overview of v2 Upgrades

The v2 intelligence upgrade enhanced all core engines with advanced capabilities:

### Payload Engine v2: WAF-Aware Generation

```
Request: generate("xss", context="attribute", waf="cloudflare")
  │
  ├─ WAF Fingerprint: Identify Cloudflare signatures in responses
  ├─ Base Payloads: Select attribute-context XSS payloads
  ├─ Mutation Pipeline:
  │   ├─ Case alternation: <ScRiPt> → <sCrIpT>
  │   ├─ Encoding chains: URL → HTML entity → Unicode
  │   ├─ Null byte insertion: <scr%00ipt>
  │   ├─ Comment injection: <scr<!---->ipt>
  │   └─ Polyglot wrapping: jaVasCript:/*-/*`/*\`/*...
  ├─ Learning Check: Filter out known-blocked payloads for this WAF
  └─ Return: Ranked payload list with bypass probability scores
```

### Analysis Engine v2: ML-Powered Assessment

```
Input: List of raw vulnerability findings
  │
  ├─ CVSS 3.1 Scoring: Auto-calculate base score per finding
  ├─ Feature Extraction: 26 features per vulnerability
  ├─ ML Classification:
  │   ├─ GradientBoosting model prediction
  │   ├─ RandomForest model prediction
  │   └─ Ensemble vote with probability calibration
  ├─ Chain Detection: Match against 17 exploit chain patterns
  │   Example: XSS in admin panel + CSRF token leak = Admin Account Takeover
  ├─ Deduplication: Group related findings, keep highest confidence
  └─ Output: Ranked vulnerabilities with CVSS, confidence, chains
```

### XSS Scanner v2: Context-Aware Detection

```
Input: endpoint URL with parameters
  │
  ├─ Step 1: Inject canary string (e.g., "bbh7x9k2")
  ├─ Step 2: Check if canary reflected in response
  │   └─ Not reflected → Skip (not reflectable)
  ├─ Step 3: Analyze HTML context around reflection
  │   ├─ Inside <script> tag → JavaScript context
  │   ├─ Inside attribute → Attribute context
  │   ├─ Inside HTML body → HTML context
  │   ├─ Inside URL → URL context
  │   └─ Inside <style> → CSS context
  ├─ Step 4: Get context-specific payloads from PayloadEngine
  ├─ Step 5: Inject payloads, check for execution indicators
  ├─ Step 6: DOM XSS analysis (source/sink pattern matching)
  └─ Step 7: Report results to LearningEngine
```

### Learning Engine v2: Continuous Improvement

```
Feedback Loop:
  Scanner finds vulnerability
    → Analyst confirms/denies (via dashboard or CLI)
      → LearningEngine.record_feedback(vuln_id, is_true_positive)
        → Feature extraction (26 features)
          → Model retraining (when threshold reached)
            → Updated predictions for future scans

WAF Payload Tracking:
  PayloadEngine sends payload against WAF
    → Response analyzed (blocked/passed)
      → LearningEngine.record_payload_result(payload, waf, success)
        → WAF-specific success rate tracking
          → Future payload selection weighted by WAF success rate
```

---

## 17. Timeout & Skip Control

When running a full pipeline, individual recon tools or LLM chunk requests can hang or take excessively long. BBHunter provides configurable timeout and skip mechanisms at every level so the pipeline always makes forward progress.

### 17.1 Recon Step Timeout

Each of the 14 recon steps (subfinder, amass, dnsx, httpx, etc.) is wrapped with a `SIGALRM`-based timeout. If a tool exceeds the allowed time, the step is **skipped** and the pipeline moves to the next step.

**Config:** `config.yaml` → `pipeline.step_timeout` (default: 600 seconds)

**Override at runtime:**
```bash
# Via environment variable
BB_STEP_TIMEOUT=300 ./run.sh all          # 5 min per step

# Via CLI flag
python3 scripts/hunt.py --step-timeout 300
python3 scripts/run_pipeline.py --step-timeout 300

# Disable timeout (no limit)
BB_STEP_TIMEOUT=0 ./run.sh recon
```

**What happens on timeout:**
- The step is killed cleanly
- Status is logged as `⏭` (skipped) in the summary table
- Any partial output already written to disk is preserved
- Pipeline continues to the next step
- DB audit trail records the timeout event

### 17.2 LLM Chunk Timeout

Each LLM chunk request to Ollama has its own timeout. If the model is slow (low VRAM, large context, GPU contention), individual chunks can be skipped rather than blocking the entire analysis.

**Config:** `config.yaml` → `pipeline.llm_chunk_timeout` (default: 300 seconds)

**Override at runtime:**
```bash
# Via environment variable
BB_CHUNK_TIMEOUT=120 ./run.sh analyze      # 2 min per chunk

# Via CLI flag
python3 scripts/llm_analyzer.py --chunk-timeout 120
python3 scripts/run_pipeline.py --chunk-timeout 120
```

**What happens on timeout:**
- The HTTP request to Ollama times out
- The chunk is marked as failed in the state file
- The consecutive failure counter increments
- Pipeline moves to the next chunk (or skips the file — see below)

### 17.3 Consecutive Failure Skip

If the LLM fails on multiple consecutive chunks (e.g., Ollama crashed, model OOM, network issue), there's no point trying the remaining chunks of that file. After N consecutive failures, the remaining chunks of the current file are skipped and the pipeline moves to the next file.

**Config:** `config.yaml` → `pipeline.max_consecutive_failures` (default: 3)

**Override at runtime:**
```bash
# Via environment variable
BB_MAX_FAILURES=5 ./run.sh analyze         # tolerate 5 failures before skip

# Via CLI flag
python3 scripts/llm_analyzer.py --max-failures 5
python3 scripts/run_pipeline.py --max-failures 5

# Never skip (process all chunks regardless of failures)
BB_MAX_FAILURES=0 ./run.sh analyze
```

**What happens on skip:**
- A warning is logged: `⚠️ N consecutive failures — skipping remaining M chunks`
- The `_state.json` records `skipped_reason`
- Any already-processed chunks are preserved in the merged analysis
- The next file in the queue is processed normally
- You can re-run with `--resume` later to retry the skipped chunks

### 17.4 Combined Example

```bash
# Aggressive timeouts for a quick scan
BB_STEP_TIMEOUT=180 BB_CHUNK_TIMEOUT=60 BB_MAX_FAILURES=2 ./run.sh all

# Or via run_pipeline.py flags
python3 scripts/run_pipeline.py \
    --step-timeout 180 \
    --chunk-timeout 60 \
    --max-failures 2

# Conservative: let everything run longer
BB_STEP_TIMEOUT=1200 BB_CHUNK_TIMEOUT=600 BB_MAX_FAILURES=10 ./run.sh all
```

### 17.5 Config File Settings

```yaml
# config.yaml
pipeline:
  step_timeout: 600          # Max seconds per recon tool step (0=no limit)
  llm_chunk_timeout: 300     # Max seconds per LLM chunk request (0=use llm.request_timeout)
  max_consecutive_failures: 3 # Skip to next file/step after N consecutive failures
```

### 17.6 How It Works Internally

```
Recon Step (e.g., amass):
  SIGALRM set to step_timeout seconds
    │
    ├─ Tool completes within timeout → ✓ continue
    │
    └─ SIGALRM fires → StepTimeoutError raised
         → Step logged as ⏭ (skipped)
         → Partial output preserved
         → Next step starts

LLM Chunk Processing:
  For each chunk in file:
    │
    ├─ Send to Ollama with timeout=llm_chunk_timeout
    │   ├─ Success → reset consecutive_failures counter
    │   └─ Failure → increment consecutive_failures
    │
    ├─ consecutive_failures >= max_consecutive_failures?
    │   ├─ Yes → skip remaining chunks, move to next file
    │   └─ No  → continue to next chunk
    │
    └─ All chunks done → merge analyses → next file
```

---

## 18. Directory Structure

```
superbot/
├── run.sh                          # Shell entry point
├── config.yaml                     # Master configuration
├── authorized_targets.yaml         # Target authorization rules
├── pyproject.toml                  # Python project metadata & dependencies
├── Dockerfile                      # Docker image definition
├── docker-compose.yml              # Multi-service composition
├── install_tools.sh                # Go recon tool installer
│
├── bbhunter/                       # Core async engine library
│   ├── __init__.py
│   ├── cli.py                      # Click CLI (679 lines)
│   ├── config.py                   # Pydantic config loading
│   ├── database.py                 # Async SQLite ORM
│   ├── logger.py                   # Structured logging (Rich)
│   ├── models.py                   # Pydantic data models
│   ├── safety.py                   # SafetyGate authorization
│   ├── tools.py                    # External tool runners
│   │
│   └── engines/
│       ├── recon/                   # Reconnaissance modules
│       │   ├── engine.py           # ReconEngine orchestrator
│       │   ├── subdomain.py        # Subdomain discovery
│       │   ├── dns_enum.py         # DNS enumeration
│       │   ├── ct_logs.py          # Certificate Transparency
│       │   ├── asn_lookup.py       # ASN/IP range lookup
│       │   ├── wayback.py          # Wayback Machine
│       │   ├── cloud_recon.py      # Cloud asset discovery
│       │   ├── github_recon.py     # GitHub dorking
│       │   └── reverse_ip.py       # Reverse IP lookup
│       │
│       ├── surface/                 # Attack surface mapping
│       │   └── engine.py           # SurfaceMappingEngine
│       │
│       ├── scanner/                 # Vulnerability scanners
│       │   ├── engine.py           # VulnerabilityScanner orchestrator
│       │   ├── base_scanner.py     # Abstract base class
│       │   ├── xss_scanner.py      # XSS v2 (context-aware)
│       │   ├── sqli_scanner.py     # SQL injection (3-phase)
│       │   ├── ssrf_scanner.py     # SSRF detection
│       │   ├── idor_scanner.py     # IDOR detection
│       │   ├── cors_scanner.py     # CORS misconfiguration
│       │   ├── open_redirect_scanner.py  # Open redirects
│       │   ├── ssti_scanner.py     # Template injection
│       │   ├── header_scanner.py   # Security headers
│       │   ├── jwt_scanner.py      # JWT vulnerabilities
│       │   └── auth_scanner.py     # Auth bypass
│       │
│       ├── analysis/                # Vulnerability analysis
│       │   └── engine.py           # AnalysisEngine v2 (706 lines)
│       │
│       ├── payloads/                # Payload generation
│       │   └── engine.py           # PayloadEngine v2 (838 lines)
│       │
│       ├── assistant/               # Manual testing guidance
│       │   └── engine.py           # ManualTestingAssistant v2
│       │
│       ├── reporting/               # Report generation
│       │   └── engine.py           # ReportEngine
│       │
│       ├── learning/                # ML & feedback
│       │   ├── engine.py           # LearningEngine v2
│       │   └── module.py           # Learning data module
│       │
│       └── dashboard/               # Web dashboard
│           └── api.py              # FastAPI REST API (743 lines)
│
├── scripts/                         # Sync pipeline tools
│   ├── run_pipeline.py             # Master orchestrator (485 lines)
│   ├── hunt.py                     # 14-step recon pipeline (1502 lines)
│   ├── llm_analyzer.py            # LLM chunk analysis (536 lines)
│   ├── generate_report.py         # Report generation (525+ lines)
│   ├── engine_bridge.py           # Scripts↔engines bridge (943 lines)
│   ├── config.py                   # Config delegation (121 lines)
│   ├── db_manager.py              # Sync SQLite operations
│   └── cleanup.py                  # Data cleanup utilities
│
├── data/                            # Runtime data (gitignored)
│   ├── bbhunter.db                 # SQLite database
│   ├── pipeline_state.json         # Pipeline checkpoint
│   └── <target>/                   # Per-target data
│       ├── 01_subdomains_inscope.txt
│       ├── ... (14 recon output files)
│       └── engines/                # Engine output files
│
├── llm_analysis/                    # LLM analysis output
│   └── <target>/
│       ├── 01_subdomains_inscope/
│       │   ├── chunk_000.json
│       │   └── _merged_analysis.txt
│       └── ... (one folder per recon file)
│
├── reports/                         # Generated reports
│   └── <target>/
│       ├── final_report.md
│       ├── findings.json
│       └── report.html
│
└── logs/                            # Application logs
```

---

## 19. Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| `subfinder: command not found` | Run `./install_tools.sh` or add `~/go/bin` to PATH |
| `Ollama connection refused` | Start Ollama: `ollama serve &` |
| `Model not found: dolphin-llama3:8b` | Pull model: `ollama pull dolphin-llama3:8b` |
| `Authorization failed` | Add target to `authorized_targets.yaml` |
| `Pipeline stuck at LLM analysis` | Check Ollama logs; model may be OOM. Reduce chunk size in config |
| `Step timed out / skipped` | Increase `BB_STEP_TIMEOUT` or set to 0 for no limit |
| `Multiple chunk failures` | Check Ollama health; increase `BB_CHUNK_TIMEOUT` or `BB_MAX_FAILURES` |
| `No vulnerabilities found` | Normal for passive-only mode. Check LLM analysis reports for manual testing leads |
| `Import errors` | Run `pip install -e .` from project root |
| `SQLite locked` | Only one pipeline instance should run at a time |

### Checking Prerequisites

```bash
./run.sh check
```

This validates:
- All Go recon tools are installed and in PATH
- Ollama is running and the model is available
- Python dependencies are installed
- Target configuration is valid

### Logs

- Pipeline logs: `logs/` directory
- Script logs: `scripts/logs/`
- Rich console output provides real-time progress bars and status

### Resetting State

```bash
# Clear pipeline state (restart from scratch)
rm data/pipeline_state.json

# Clear LLM analysis cache (re-analyze all data)
rm -rf llm_analysis/<target>/

# Clear all data for a target
rm -rf data/<target>/
```

---

## Appendix: Command Quick Reference

```bash
# ─── Full Pipeline ───────────────────────
./run.sh all                           # Complete pipeline
./run.sh target example.com            # Pipeline for specific target
./run.sh resume                        # Resume from checkpoint

# ─── Individual Phases ───────────────────
./run.sh recon                         # Phase 1: Recon only
./run.sh analyze                       # Phase 2: LLM analysis only
./run.sh report                        # Phase 3: Report only

# ─── Prerequisites ───────────────────────
./run.sh check                         # Verify all tools installed

# ─── Timeout / Skip Control ─────────────
BB_STEP_TIMEOUT=300 ./run.sh all       # 5 min per recon tool
BB_CHUNK_TIMEOUT=120 ./run.sh analyze  # 2 min per LLM chunk
BB_MAX_FAILURES=5 ./run.sh all         # Skip file after 5 chunk failures
python3 scripts/run_pipeline.py --step-timeout 300 --chunk-timeout 120 --max-failures 5

# ─── CLI Commands ────────────────────────
bbhunter recon example.com             # Engine-based recon
bbhunter surface example.com           # Map attack surface
bbhunter scan example.com              # Scan for vulnerabilities
bbhunter full example.com              # Complete engine pipeline
bbhunter payloads xss -c html -w cf    # Generate payloads
bbhunter dashboard                     # Start web dashboard
bbhunter learning stats                # ML model statistics
bbhunter tools status                  # External tool status
bbhunter decode <data>                 # Auto-decode data

# ─── Docker ──────────────────────────────
docker-compose up -d                   # Start all services
docker-compose exec bbhunter ./run.sh  # Run inside container
docker-compose logs -f                 # View logs
```

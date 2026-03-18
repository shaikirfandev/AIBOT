# BBHunter Deep Functional Audit Report

**Date:** 2025-01-XX  
**Scope:** Every engine, module, and pipeline component in `/Users/macbook/superbot/`  
**Codebase:** ~15,000 LOC across 60+ Python files  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Core Framework](#2-core-framework)
3. [CLI & Task Queue](#3-cli--task-queue)
4. [Tools Layer](#4-tools-layer)
5. [Recon Engine](#5-recon-engine)
6. [Surface Mapping Engine](#6-surface-mapping-engine)
7. [Scanner Engine](#7-scanner-engine)
8. [Analysis Engine](#8-analysis-engine)
9. [Payload Engine](#9-payload-engine)
10. [Assistant Engine](#10-assistant-engine)
11. [Learning Engine](#11-learning-engine)
12. [Reporting Engine](#12-reporting-engine)
13. [Dashboard](#13-dashboard)
14. [Scripts Pipeline](#14-scripts-pipeline)
15. [Infrastructure](#15-infrastructure)
16. [Cross-Cutting Issues](#16-cross-cutting-issues)
17. [Priority Fix List](#17-priority-fix-list)

---

## 1. Executive Summary

BBHunter is an ambitious bug bounty automation suite with a **dual-track architecture**: a library-style engine system (`bbhunter/`) and a script-based recon pipeline (`scripts/`). The surface area is large and the ideas are solid. However, the system has **critical integration bugs that prevent end-to-end execution**, significant duplication, and multiple code paths that silently fail or produce no output.

### Verdict by Component

| Component | Status | Severity |
|-----------|--------|----------|
| Config & Models | ✅ Works | Minor issues |
| Safety Gate | ⚠️ Partially broken | Singleton inconsistency |
| Database | ⚠️ Two separate DBs | Schema divergence |
| CLI `full` pipeline | ❌ Broken | Type mismatches crash it |
| Celery tasks | ❌ Broken | Type mismatches crash it |
| Dashboard full scan | ❌ Broken | Same pipeline bugs |
| Recon Engine (library) | ✅ Works | Duplication |
| Scanner Engine | ⚠️ Silently does nothing | Empty default categories |
| Surface Engine | ✅ Works | Minor |
| Analysis Engine | ✅ Works | Good quality |
| Payload Engine | ✅ Works | Comprehensive |
| Assistant Engine | ✅ Works | Good quality |
| Learning Engine | ⚠️ Duplicated | Two implementations |
| Reporting Engine | ⚠️ Output mismatch | CLI can't consume it |
| Scripts pipeline | ✅ Works | Best-tested path |
| Engine Bridge | ✅ Works | Solid integration |

**Bottom line:** The `scripts/` pipeline (hunt.py → llm_analyzer.py → engine_bridge.py → generate_report.py) is the only path that actually works end-to-end. The `bbhunter/` library pipeline (CLI `full` command, Celery tasks, Dashboard full scan) is **broken due to type mismatches between engines**.

---

## 2. Core Framework

### 2.1 config.py — ✅ Solid

**What works well:**
- Clean Pydantic-settings architecture with 16 typed config models
- YAML loading with `_resolve_env_vars()` for `${ENV_VAR}` syntax
- Singleton pattern via `get_config()` / `_config` global

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | `_resolve_env_vars()` only handles full-string env vars (`${FOO}`), not partial interpolation (`prefix_${FOO}_suffix`) | Low | config.py L40-50 |
| 2 | `scanner.categories` defaults to **empty list** `[]` in the Pydantic model, but config.yaml defines 14 categories. If config.yaml fails to load, the scanner runs **zero scanners** silently | **High** | config.py ScannerConfig |
| 3 | No validation that referenced files (authorization_file, dns_wordlist) actually exist at startup | Low | config.py |

### 2.2 models.py — ✅ Good

**What works well:**
- Clean Pydantic v2 models with comprehensive enum types
- Forward reference fix with `Endpoint.model_rebuild()` at module bottom
- `ScanResult` has dict-like interface (`get()`, `__getitem__`, `items()`) delegating to `metadata` — clever pattern for inter-engine data passing

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | `Severity` has both `INFO = "info"` and `INFORMATIONAL = "informational"` — code inconsistently uses both throughout the codebase | Medium | models.py L15-20 |
| 2 | `VulnCategory` has 22 categories including `CSRF` and `RATE_LIMIT`, but **no scanner exists for either** | Medium | models.py |
| 3 | `ScanResult.metadata` is the only data carrier between engines. No typed fields for `subdomains`, `endpoints`, `vulnerabilities` — everything goes through string-keyed dict access | Medium | models.py |

### 2.3 safety.py — ⚠️ Singleton Inconsistency

**What works well:**
- Thorough scope checking with fnmatch patterns
- Rate limiting configuration per target
- Banned method enforcement
- `get_safety_gate()` singleton function

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | **Module-level `safety = SafetyGate()`** in tools.py creates a NEW instance (not the singleton), which loads authorized_targets.yaml independently | **High** | tools.py L25 |
| 2 | `cli.py` creates `SafetyGate()` fresh in **every command handler** — each reads YAML again | Medium | cli.py (multiple) |
| 3 | `dashboard/api.py` creates its own `SafetyGate()` at module level | Medium | api.py L30 |
| 4 | `tasks.py` correctly uses `get_safety_gate()` | ✅ | tasks.py |
| 5 | `engine_bridge.py` patches the singleton gate directly — smart, but shows the design problem | Note | engine_bridge.py L310 |

**Impact:** Different SafetyGate instances may have different authorized target lists if the YAML file changes, or if `engine_bridge.py` injects targets into one instance while tools.py uses another.

### 2.4 database.py — ⚠️ Two Separate Database Systems

**What works well:**
- SQLAlchemy ORM with both async (`aiosqlite`) and sync (`create_engine`) support
- Proper table definitions for targets, assets, endpoints, vulnerabilities, scans, exploit chains, feedback

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | **Two completely separate database systems**: `bbhunter/database.py` (SQLAlchemy ORM) and `scripts/db_manager.py` (raw SQLite). Different schemas, different tables, no shared access. | **Critical** | database.py vs db_manager.py |
| 2 | `database.py` has ORM models but **no code anywhere in bbhunter/ actually writes to the database** during engine execution. Results stay in ScanResult.metadata dicts. | **Critical** | database.py |
| 3 | `scripts/db_manager.py` has 11 tables vs `database.py`'s 7 ORM models — schemas diverged. db_manager.py has `llm_chunks`, `llm_analyses`, `technologies`, `parameters`, `action_log` that don't exist in database.py | High | Both files |
| 4 | No migration support. Both use `CREATE TABLE IF NOT EXISTS` / `create_all()` — any schema change requires manual DB deletion | Medium | Both files |
| 5 | JSON fields stored as Text columns with no automatic serialization/deserialization helpers | Low | database.py |
| 6 | No conversion helpers between SQLAlchemy ORM rows and Pydantic models | Medium | database.py |

### 2.5 exceptions.py — ✅ Excellent

Complete, well-organized exception hierarchy. No issues found. All exception types are used across the codebase.

### 2.6 logger.py — ✅ Good

- `ActionLogger` provides JSON-lines audit trail — well designed
- `get_logger()` and `get_action_logger()` singletons work correctly
- Thread-safe via `threading.Lock` on ActionLogger

**Minor issue:** `ActionLogger` writes to `./logs/actions.jsonl` hardcoded, not from config.

---

## 3. CLI & Task Queue

### 3.1 cli.py — ⚠️ `full` Pipeline Broken

**What works well:**
- Clean Click command group with 8 top-level commands
- Rich console output with progress bars, tables, panels
- Tool status checking (`tools status`)
- Individual engine commands (recon, surface, scan) work in isolation

**Critical Bugs:**

| # | Bug | Severity | Location |
|---|-----|----------|----------|
| 1 | **`full` command type mismatch:** `recon_results.get("subdomains")` returns list of strings, passed to `SurfaceMappingEngine.run()` as `subdomains` — but surface engine expects seed URLs, not bare domain strings. Missing `https://` prefix causes silent failure or no crawling. | **Critical** | cli.py L220-240 |
| 2 | **`full` command type mismatch:** `surface_results.get("endpoints")` returns list of **dicts** (from ScanResult.metadata). These are passed to `VulnerabilityScanner.run()` which expects `list[Endpoint]` Pydantic objects. Scanner will crash or silently skip. | **Critical** | cli.py L250 |
| 3 | **`report` command format mismatch:** iterates over `ReportEngine.generate_all_reports()` output expecting `list[dict]` with `.get("format")` and `.get("content")` keys, but the engine returns `list[str]` (raw content strings) | **Critical** | cli.py L350+ |
| 4 | Each Click command creates a fresh `SafetyGate()` (not singleton) | Medium | cli.py (multiple) |

### 3.2 tasks.py — ⚠️ Same Pipeline Bugs

**Issues:**

| # | Bug | Severity | Location |
|---|-----|----------|----------|
| 1 | `run_full_pipeline` has same type mismatch chain as cli.py `full` — raw dicts passed between engines instead of Pydantic models | **Critical** | tasks.py L80-130 |
| 2 | Celery tasks use `model_dump()` on ScanResult to return JSON-serializable data, but the consuming code would need to reconstruct Pydantic objects | Medium | tasks.py |
| 3 | No error handling on inter-engine data conversion | Medium | tasks.py |

---

## 4. Tools Layer (tools.py)

**What works well:**
- 20 external tool wrappers covering recon, scanning, probing, secrets, params, WAF detection, crawling, notifications
- All wrappers follow consistent pattern: availability check → safety gate → subprocess → parse output
- `TOOL_REGISTRY` dict enables dynamic tool discovery
- `get_tool_runner()` factory pattern
- ToolResult dataclass consolidates raw output, parsed data, assets, endpoints, vulnerabilities

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | Module-level `safety = SafetyGate()` — not singleton (see §2.3) | High | tools.py L25 |
| 2 | `DalfoxRunner` and `SqlmapRunner` create temp files but use `delete=False`. Cleanup in `finally` block is correct, but if the process is killed, orphan temp files remain | Low | tools.py |
| 3 | All Vulnerability objects created by tools use `target_id="ext"` hardcoded — no way to correlate to actual target | Medium | tools.py (multiple runners) |
| 4 | `NmapRunner` parses nmap text output line-by-line instead of parsing the XML output file it creates with `-oX` — the XML file is created but never read | Medium | tools.py L730 |
| 5 | `run_cmd()` async helper not visible in read portion but all runners depend on it | Note | tools.py |

---

## 5. Recon Engine

### 5.1 engine.py — ✅ Good Orchestration

- 3-phase execution (passive parallel → active parallel → cloud)
- Asset deduplication by (type, value)
- `quick_recon()` for lightweight mode

### 5.2 Sub-modules

| Module | Status | Notes |
|--------|--------|-------|
| subdomain.py | ⚠️ Duplication | `_crtsh()` duplicates `ct_logs.py._crtsh()` exactly |
| dns_enum.py | ✅ Good | Comprehensive record types, zone transfer attempts |
| wayback.py | ✅ Good | CDX API + Common Crawl |
| ct_logs.py | ⚠️ Duplication | crt.sh logic duplicated from subdomain.py |
| github_recon.py | ⚠️ Dead code | `analyze_for_secrets()` method exists but is **never called** from `search()` |
| cloud_recon.py | ✅ Works | S3/Azure/GCP bucket brute-forcing |
| asn_lookup.py | ⚠️ Insecure | Uses HTTP (not HTTPS) for ip-api.com requests | 
| reverse_ip.py | ✅ Works | Simple HackerTarget wrapper |

**Duplicate Code:** `SubdomainEnumerator._crtsh()` and `CTLogEnumerator._crtsh()` contain identical logic for querying crt.sh JSON API. One should call the other or both should call a shared helper.

**Dead Code:** `GitHubRecon.analyze_for_secrets()` has SECRET_PATTERNS with 8 regex patterns for API keys, AWS keys, JWT tokens, private keys, passwords, etc. — but the `search()` method only returns raw GitHub search results without ever calling `analyze_for_secrets()`.

---

## 6. Surface Mapping Engine

**What works well:**
- Recursive crawl with depth control and scope checking
- JS analysis extracts hidden API endpoints via regex patterns
- API discovery probes 30+ common API/docs paths
- Technology fingerprinting for 15+ frameworks
- WAF detection for 7 WAFs
- Clean async execution with httpx

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | `_discover_apis()` creates a **new httpx.AsyncClient per request** inside a loop over 30+ paths × 2 base URLs — up to 60+ client instantiations instead of one shared client | Medium | surface/engine.py L340 |
| 2 | `_detect_waf()` sends an actual XSS payload (`<script>alert(1)</script>`) in the URL — this is **active probing** that violates passive-only target rules and may trigger alerts | **High** | surface/engine.py L400 |
| 3 | No rate limiting on API discovery requests — fires requests as fast as possible across 60+ URLs | Medium | surface/engine.py |
| 4 | JS URLs extracted from HTML are joined without proper URL resolution (relative URLs with `../` won't resolve correctly) | Low | surface/engine.py |

---

## 7. Scanner Engine

### 7.1 Orchestrator (engine.py) — ⚠️ Silent No-Op by Default

**Critical Issue:** If `categories` parameter is not explicitly provided AND config.yaml fails to load, `self.config.scanner.categories` defaults to `[]` (empty list from Pydantic model default). The scanner then runs **zero scanners** and returns an empty result with no warning.

Config.yaml does define 14 categories, but the Pydantic model default is `[]`, creating a silent failure mode.

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | Empty default categories = zero scanners run silently | **Critical** | scanner/engine.py L55-65 |
| 2 | Scanner mapping uses string keys ("xss", "sqli") but VulnCategory enum values — no validation that provided categories match scanner names | Medium | scanner/engine.py |
| 3 | Categories `csrf`, `rate_limit`, `file_upload`, `path_traversal`, `command_injection` exist in VulnCategory but have **no scanner implementation** | Medium | scanner/engine.py |

### 7.2 Individual Scanners

| Scanner | Status | Key Issues |
|---------|--------|------------|
| **xss_scanner.py** | ✅ Good | Context-aware (5 contexts), canary-based reflection, DOM XSS detection. PayloadEngine + LearningEngine integration works. |
| **sqli_scanner.py** | ⚠️ FP-prone | Boolean blind uses 50-byte response length threshold — extremely fragile, will produce FPs on dynamic content |
| **cors_scanner.py** | ✅ Good | Tests arbitrary origin, wildcard, null, subdomain reflection |
| **ssrf_scanner.py** | ⚠️ Limited | Only tests parameters whose names match a hardcoded `SSRF_PARAMS` list — misses non-obvious parameter names. Only tests query params, not POST body/headers/path |
| **ssti_scanner.py** | ⚠️ Duplicate | `${7*7}` appears twice in PAYLOADS list. Covers 7 template engines. Math-based detection is sound. |
| **jwt_scanner.py** | ⚠️ Limited | Only finds JWTs in responses — doesn't test JWT manipulation on authenticated endpoints. Weak secret list has only ~10 common passwords. |
| **idor_scanner.py** | ⚠️ Redundant requests | `_test_path_idor` makes a redundant baseline request inside the loop (should be outside). Low confidence (0.55) is appropriate. |
| **auth_scanner.py** | ⚠️ Naive | Hardcodes form field names (`username`/`password`) — won't work with `email`/`passwd`/`login`/`user` etc. Only 5 credential pairs. |
| **header_scanner.py** | ✅ Good | Deduplicates by host. Checks 7 security headers + info leakage headers. |
| **open_redirect_scanner.py** | ✅ Good | Tests HTTP redirects + DOM-based (meta refresh, window.location). Has bypass payloads. |

**All Scanners — Shared Issues:**

| # | Issue | Severity |
|---|-------|----------|
| 1 | **Only test query parameters in GET requests.** No POST body parameter testing, no header injection, no path parameter testing. | **High** |
| 2 | No cookie/session handling across requests — can't test authenticated endpoints | **High** |
| 3 | No proxy support — can't route through Burp/ZAP for verification | Medium |
| 4 | No rate limiting — scanners fire requests as fast as possible | Medium |
| 5 | `base_scanner.py` uses `verify=False` for all HTTPS — correct for testing but no option to enable verification | Low |
| 6 | `follow_redirects=False` in base scanner means scanners miss vulnerabilities behind redirects | Medium |

---

## 8. Analysis Engine — ✅ Strong

**What works well:**
- Multi-layer FP reduction: confidence threshold → heuristics → ML prediction
- 17 static exploit chain patterns + dynamic chain discovery (same-endpoint multi-vuln)
- CVSS 3.1 estimation with per-category defaults
- Contextual correlation (same parameter across endpoints, same path prefix, severity clustering)
- Temporal analysis (new vs previously-seen findings)
- Attack graph generation with nodes/edges for visualization
- Impact assessment across 7 risk categories

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | `urllib_safe()` helper at module bottom uses `urllib.parse.quote` inside the function — should be imported at top level | Low | analysis/engine.py L700 |
| 2 | `_is_likely_fp()` XSS heuristic checks `vuln.response` but `Vulnerability` model has no `response` field — this attribute access silently returns None via Pydantic, meaning the heuristic never fires | Medium | analysis/engine.py L330 |
| 3 | `assess_severity()` fallback logic: "if not auth in URL, upgrade MEDIUM to HIGH" is backwards — should upgrade if auth IS in URL (auth bypass is more severe) | Medium | analysis/engine.py L620 |

---

## 9. Payload Engine — ✅ Comprehensive

**What works well:**
- WAF fingerprinting for 10 WAFs with header + body + status code analysis
- Multi-layer encoding chains (URL, HTML, Unicode, hex, base64, jschar)
- Response-adaptive mutation (analyze filtered chars → generate bypass payloads)
- Technology-stack-aware payload selection via `TECH_PAYLOAD_MAP`
- Comprehensive payload libraries for 10 vulnerability categories
- WAF-specific bypass payloads per WAF per category
- Polyglot payloads for initial sweeps
- LearningEngine integration for ranked payloads by historical effectiveness
- 3 API entry points: `generate()`, `get_payloads()`, `generate_payloads()` — all work

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | `generate_xss_payloads()` parameter `target_url` isn't in the function signature — `generate()` dispatcher passes it but the function ignores unknown kwargs via dispatcher lambda, so it silently drops it | Low | payloads/engine.py |
| 2 | `_case_mutations()` uses `random.random()` — mutations are non-deterministic, making payload sets unreproducible across runs | Low | payloads/engine.py |
| 3 | Some mutation methods (encoding, obfuscation) apply to ALL payloads including already-mutated ones, causing payload explosion. `generate_xss_payloads` deduplicates with `dict.fromkeys()` which helps, but count can still be very high | Low | payloads/engine.py |

---

## 10. Assistant Engine — ✅ Well Designed

**What works well:**
- Tech-specific playbooks for 6 technologies (GraphQL, JWT, REST API, WordPress, OAuth, File Upload)
- URL pattern → attack map (10+ patterns)
- Parameter name → attack type mapping
- Business logic suggestions based on endpoint semantics (payments, account ops, 2FA, votes)
- Response analysis with sensitive data detection (15+ patterns)
- Security header checking
- Data decoding (base64, URL, hex, JWT)
- CORS testing helper with curl commands
- Risk score calculation (0-10 scale)
- LearningEngine integration for ranking by historical effectiveness

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | `recommend_payloads()` blocked chars analysis logic is inverted — checks `if ch not in resp` (char NOT in response = probably NOT blocked). Should check if payloads containing that char get different responses vs clean requests. | Medium | assistant/engine.py L580 |
| 2 | `SENSITIVE_PATTERNS` and `SECURITY_HEADERS` are referenced but defined as module-level constants — they'd need to be verified they exist | Low | assistant/engine.py |

---

## 11. Learning Engine — ⚠️ Duplicated

### Two separate implementations that do the same thing:

**`learning/engine.py` (534 lines) — ML-based:**
- GradientBoosting + RandomForest for FP detection
- 25+ engineered features (NLP from evidence text, URL patterns, payload complexity)
- Cross-validation reporting during training
- Payload effectiveness tracking per category and per WAF
- Trend analysis across scan runs
- Persists to `data/models/` directory

**`learning/module.py` (206 lines) — Simple JSON-based:**
- Incremental model update via weighted averages
- JSON-based persistence (`data/models/training_data.json`)
- `record_feedback()`, `adjust_confidence()`, `get_statistics()`

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | **Two learning systems**: `LearningEngine` and `LearningModule` with overlapping functionality. `engine_bridge.py` tries LearningEngine first, falls back to LearningModule if sklearn is missing — confirming they're redundant. | **High** | learning/ |
| 2 | `LearningModule.adjust_confidence()` adjusts a vulnerability's confidence but doesn't persist the change anywhere — in-memory only | Medium | learning/module.py |
| 3 | `LearningEngine` requires `min_samples=100` before training (configurable) — until 100 feedback samples are collected, ML model is None and all FP predictions fall back to heuristics | Note | learning/engine.py |
| 4 | Neither learning system persists its model as a proper pickle/joblib file — `LearningEngine` saves to JSON (can't serialize sklearn models to JSON), `LearningModule` saves to JSON | Medium | Both |

---

## 12. Reporting Engine — ⚠️ Output Format Mismatch

**What works well:**
- Three Jinja2 templates: HackerOne, Bugcrowd, Executive Summary
- JSON export format
- Proper CVSS scoring display
- Exploit chain visualization in reports
- Methodology section with tool listing

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | **`generate_all_reports()` returns `list[str]`** (raw content strings), but `cli.py` `report` command iterates expecting `list[dict]` with `.get("format")` and `.get("content")` keys — **crashes** | **Critical** | reporting/engine.py + cli.py |
| 2 | Reports are **not saved to disk** by the engine — only returned as strings. The caller (CLI, dashboard, engine_bridge) must handle file writing. engine_bridge.py does this correctly, CLI does not. | Medium | reporting/engine.py |
| 3 | Jinja2 templates use `BaseLoader()` (string-based) — templates are embedded as Python strings, not external files. Works but makes template customization hard. | Low | reporting/engine.py |
| 4 | Executive summary template references `analysis.risk_scores` but AnalysisEngine returns `impact_summary` — field name mismatch may produce empty sections | Medium | reporting/engine.py |

---

## 13. Dashboard — ⚠️ Functional but Fragile

**What works well:**
- Full-featured FastAPI REST API with 15+ endpoints
- WebSocket for real-time scan updates with auto-reconnect in frontend
- API key authentication with auto-generation warning
- Inline SPA dashboard with dark theme (full HTML/CSS/JS embedded)
- CORS configuration
- All engine endpoints work individually (recon, surface, scan, payloads, assistant, analysis, feedback, learning stats, reports)
- Clean Pydantic request models

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | **In-memory `active_scans` dict** — all scan state lost on restart. No persistence to database. | **High** | api.py L40 |
| 2 | **Full scan pipeline has same type mismatch bugs** as cli.py `full` — dicts passed between engines where Pydantic objects expected | **Critical** | api.py L300-370 |
| 3 | No WebSocket authentication — anyone can connect and receive scan data | Medium | api.py L590 |
| 4 | `ws_connections` list has no locking — race condition if connections added/removed concurrently during broadcast | Medium | api.py |
| 5 | Dashboard API key in config.yaml is `"CHANGE-ME-IN-PRODUCTION"` — auto-generated replacement is logged to console, not persisted anywhere | Medium | api.py |
| 6 | Frontend JS makes API calls without API key header — all authenticated endpoints will return 401 | **High** | api.py (DASHBOARD_HTML) |
| 7 | No HTTPS — dashboard runs on HTTP. Dockerfile EXPOSE is 8443 suggesting HTTPS was intended but not implemented | Medium | Dockerfile + api.py |

---

## 14. Scripts Pipeline

### 14.1 scripts/config.py — ✅ Good Bridge

Delegates to `bbhunter.config` while adding script-specific paths. Has `reload_target()` for runtime target switching.

**Issue:** Hardcoded `"doordash.com"` as fallback target if env var and config both missing.

### 14.2 scripts/hunt.py — ✅ Best-Tested Path (1571 lines)

**What works well:**
- 14-step passive recon pipeline with clear step separation
- Each step: run tool → filter scope → store in DB → LLM analyze output
- Rich progress bars with ETA
- Resume capability via `--from-step`
- DB persistence of all findings via `db_manager.py`
- Scope filtering respects out-of-scope domains, wildcards, and paths
- Rate limiting via `time.sleep()` between requests
- Required header injection per target rules

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | Uses `signal.SIGALRM` for step timeouts — **Unix-only**, crashes on Windows | Medium | hunt.py L180 |
| 2 | `run_tool()` uses `subprocess.run()` (sync) in an otherwise sync pipeline — fine, but means no concurrent tool execution | Low | hunt.py |
| 3 | Step `header_analysis` calls `_db.store_vulnerability()` (singular) inside a loop — should batch these | Low | hunt.py L1180 |
| 4 | `parse_llm_findings()` is called but definition not in hunt.py — must be imported from elsewhere or missing | Medium | hunt.py L400 |
| 5 | `filter_in_scope()` is called everywhere but read code doesn't show its definition clearly — relies on `SafetyChecker` class in hunt.py | Note | hunt.py |

### 14.3 scripts/llm_analyzer.py — ✅ Solid

- Chunk-based analysis via Ollama API
- Detailed 3-pass system prompt (Discovery → Validation → Attack Chains)
- File-specific context prompts for each recon data type
- Cross-reference context from previously analyzed files
- Exponential backoff retry on LLM failures
- Resume capability with per-chunk state files
- DB storage of every chunk + merged analysis

**Minor issue:** `_chunk_timeout` and `_max_consecutive_failures` are module-level globals mutated by CLI args — works but fragile.

### 14.4 scripts/engine_bridge.py — ✅ Best Integration Code (943 lines)

**What works well:**
- Properly loads recon file data and converts to bbhunter Pydantic models
- Patches `bbhunter.config` and `SafetyGate` singleton before running engines
- Correct engine execution order: Surface → Scanner → Analysis → Payloads → Assistant → Reporting → Learning
- Proper error handling with fallback results per engine
- File output + DB storage of all results
- Respects target rules (forces passive-only scanner categories when `no_automated_scanners` is true)
- LearningEngine → LearningModule fallback if sklearn missing

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | `run_surface_engine()` converts scan metadata endpoints via `Endpoint(**ep)` — if metadata dicts don't match Endpoint model fields exactly, this crashes | Medium | engine_bridge.py L380 |
| 2 | `run_scanner_engine()` same pattern: `Vulnerability(**v)` from metadata dicts | Medium | engine_bridge.py L430 |
| 3 | `run_analysis_engine()` calls `engine.analyze(vulns)` but AnalysisEngine.run() is the async interface — `analyze()` must be a sync wrapper. If it doesn't exist, this crashes. | Medium | engine_bridge.py L460 |

### 14.5 scripts/db_manager.py — ✅ Comprehensive (845 lines)

- 11-table schema covering all pipeline data
- WAL journal mode, foreign keys enabled
- Bulk insert methods with deduplication
- `get_stats()` aggregation query
- Proper UUID-based primary keys

**Issue:** Completely separate from `bbhunter/database.py` — two databases with divergent schemas (see §2.4).

### 14.6 scripts/generate_report.py — ✅ Works

LLM-based report generation: collect analyses → chunk → extract findings → consolidate → save.

### 14.7 scripts/cleanup.py — ✅ Good

Rich UI with progress bars, dry-run mode, per-target or global cleanup.

### 14.8 scripts/run_pipeline.py — ✅ Good Orchestrator

4-phase pipeline (recon → analyze → engines → report) with resume capability and phase selection.

---

## 15. Infrastructure

### 15.1 Docker

- **Dockerfile:** Installs Go tools (subfinder, httpx, dnsx, katana, gau, waybackurls, hakrawler). Non-root user. Healthcheck. Good.
- **docker-compose.yml:** 3 services (app, redis, worker). Proper volume mounts. Redis healthcheck dependency.

**Issues:**

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | Dockerfile installs Go tools but NOT nuclei, sqlmap, ffuf, feroxbuster, nmap, amass, dalfox, trufflehog, gitleaks, arjun, paramspider, wafw00f, whatweb, naabu, notify — most tool wrappers in tools.py will report "not installed" | Medium | Dockerfile |
| 2 | Celery worker entrypoint references `bbhunter.tasks` — correct module path | ✅ | docker-compose.yml |
| 3 | No Ollama service in compose — LLM features won't work without external Ollama | Medium | docker-compose.yml |

### 15.2 pyproject.toml

- Declares `weasyprint>=60.0` as dependency but no code imports it (PDF generation not implemented)
- Declares `shodan>=1.31.0` but recon.passive.enable_shodan defaults to false and no Shodan integration code exists
- Declares `alembic>=1.13.0` but no Alembic migration configuration exists
- Declares `python-whois>=0.8.0` but no code imports it
- Declares `aiohttp>=3.9.0` but all HTTP is done via `httpx`

### 15.3 config.yaml

Well-structured. Defines scanner categories that override the empty Pydantic default. LLM config points to Ollama. Target rules for DoorDash are comprehensive.

**Issue:** `dashboard.secret_key: "CHANGE-ME-IN-PRODUCTION"` — should be env var reference.

---

## 16. Cross-Cutting Issues

### 16.1 The Pipeline Is Broken (Engines Can't Talk to Each Other)

The central problem: **ScanResult.metadata is an untyped Dict[str, Any]**, and each engine puts data in using string keys. When the next engine reads from it, there's no guarantee the keys match or the values are the right type.

**Specific breakage chain in `cli.py full` / `tasks.py run_full_pipeline` / `api.py full_scan`:**

```
ReconEngine.run() → ScanResult(metadata={"subdomains": ["sub1.example.com", ...], ...})
                                                ↓
SurfaceMappingEngine.run(domain, subdomains)  ← receives list[str] bare domains
    → needs URLs like "https://sub1.example.com" to crawl
    → silently fails crawling because bare domains aren't valid URLs
                                                ↓
SurfaceMappingEngine → ScanResult(metadata={"endpoints": [{...dict...}, ...]})
                                                ↓
VulnerabilityScanner.run(domain, endpoints)   ← receives list[dict]
    → expects list[Endpoint] Pydantic objects
    → crashes on attribute access (.url, .parameters)
```

**engine_bridge.py solves this** by manually converting between formats at each step. The library pipeline doesn't.

### 16.2 Two Parallel Systems That Don't Share State

| Aspect | bbhunter/ library | scripts/ pipeline |
|--------|-------------------|-------------------|
| Database | SQLAlchemy ORM (async) — **never written to** | Raw SQLite (sync) — fully used |
| Config | Pydantic-settings + YAML | Delegates to bbhunter.config + adds paths |
| Safety | SafetyGate (multiple instances) | SafetyChecker (separate class) + delegates |
| Execution | Async (asyncio) | Sync (subprocess.run) + async in bridge |
| LLM | Not integrated in engines | Fully integrated (llm_analyzer) |
| Output | ScanResult.metadata dicts | Files + SQLite DB |

### 16.3 Missing Features for Real Bug Bounty Hunters

| Feature | Status |
|---------|--------|
| CSRF scanner | **Missing** — VulnCategory.CSRF exists but no scanner |
| Rate limit testing | **Missing** — VulnCategory.RATE_LIMIT exists but no scanner |
| File upload scanner | **Missing** — config lists it but no scanner |
| Path traversal scanner | **Missing** — PayloadEngine generates payloads but no scanner |
| Command injection scanner | **Missing** — PayloadEngine generates payloads but no scanner |
| POST parameter testing | **Missing** — all scanners only test GET query params |
| Authentication handling | **Missing** — no way to provide session cookies/tokens for authenticated scanning |
| Proxy support | **Missing** — can't route through Burp/ZAP |
| Screenshot capture | **Missing** — config `include_screenshots: true` but no implementation |
| Shodan integration | **Missing** — dependency declared, config exists, no code |
| Censys integration | **Missing** — config exists, no code |
| VirusTotal integration | **Missing** — config exists, no code |
| PDF report output | **Missing** — weasyprint dependency declared, no code |
| HTML report output | **Missing** — only Markdown and JSON |
| Alembic migrations | **Missing** — dependency declared, no config |

### 16.4 Dead Code Summary

| Code | Location | Reason |
|------|----------|--------|
| `GitHubRecon.analyze_for_secrets()` | recon/github_recon.py | Never called from `search()` |
| `LearningModule` | learning/module.py | Entirely superseded by `LearningEngine` |
| Nmap XML output file | tools.py NmapRunner | Created with `-oX` but never parsed |
| `database.py` ORM write operations | database.py | No engine code writes to DB |
| `ScanResult` dict-interface `items()`, `__contains__` | models.py | Not used by any consumer |

### 16.5 Race Conditions

| Location | Issue |
|----------|-------|
| `dashboard/api.py` `active_scans` dict | Concurrent writes from background tasks + reads from API endpoints, no locking |
| `dashboard/api.py` `ws_connections` list | Modified during iteration in `broadcast()` when clients disconnect |
| `LearningEngine` training data | File-based persistence with no locking — concurrent scan tasks could corrupt |

---

## 17. Priority Fix List

### P0 — Must Fix (Pipeline Broken)

1. **Fix inter-engine data conversion in `cli.py full`, `tasks.py run_full_pipeline`, `dashboard/api.py _run()`**: Convert ScanResult metadata dicts to Pydantic model objects between each engine call. Use engine_bridge.py's approach as reference.

2. **Fix ReportEngine output / CLI consumption mismatch**: Either make `generate_all_reports()` return `list[dict]` with format/content keys, or fix CLI to consume `list[str]`.

3. **Fix scanner default categories**: Change Pydantic model default from `[]` to the full category list, or add a warning/error when categories is empty.

### P1 — Should Fix (Functional Gaps)

4. **Unify SafetyGate usage**: Remove all `SafetyGate()` direct instantiation. Use `get_safety_gate()` everywhere.

5. **Unify database systems**: Either extend `bbhunter/database.py` ORM to match `scripts/db_manager.py` schema, or have the library engines use db_manager.py. Currently all engine execution through the library path produces zero database records.

6. **Implement POST parameter testing in scanners**: At minimum, XSS and SQLi scanners should test POST parameters.

7. **Add authentication/session handling**: Allow passing cookies/headers/tokens for authenticated endpoint scanning.

8. **Fix Dashboard frontend API key**: Frontend JS doesn't send API key header — all authenticated endpoints return 401.

### P2 — Should Fix (Code Quality)

9. **Remove duplicate crt.sh code**: Extract shared helper used by both subdomain.py and ct_logs.py.

10. **Remove LearningModule**: Delete `learning/module.py` — LearningEngine already has sklearn fallback handling.

11. **Wire up `github_recon.analyze_for_secrets()`**: Call it from `search()` to actually detect secrets in search results.

12. **Fix Nmap XML parsing**: Parse the `-oX` output file instead of stdout text parsing.

13. **Add missing scanners**: CSRF, rate limit, file upload, path traversal, command injection.

14. **Fix `assess_severity()` auth URL logic**: Currently upgrades severity when auth NOT in URL — should be opposite.

15. **Fix `_is_likely_fp()` response field access**: Vulnerability model has no `response` field — the heuristic never fires.

### P3 — Nice to Have

16. Add Alembic migration support or remove the dependency.
17. Add proxy support for scanner verification.
18. Remove unused dependencies (weasyprint, shodan, python-whois, aiohttp).
19. Add Windows support (replace SIGALRM with threading-based timeouts).
20. Add Ollama service to docker-compose.yml.
21. Implement Shodan/Censys/VirusTotal integrations or remove from config.
22. Add proper sklearn model serialization (joblib) to LearningEngine.

---

*End of audit report.*

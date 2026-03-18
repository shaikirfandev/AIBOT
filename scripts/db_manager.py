#!/usr/bin/env python3
"""
BBHunter - Database Manager (SQLite Bridge)
=============================================
Connects the scripts/ pipeline to a real SQLite database.
Stores targets, assets, endpoints, vulnerabilities, LLM analyses,
scan runs — everything queryable & persistent across runs.

Uses SYNC SQLite (no async needed — the pipeline is sequential).
Maps to bbhunter.models Pydantic types where possible.

Tables:
  targets        – authorized target domains + scope config
  scans      – each pipeline execution (start, end, status)
  assets         – subdomains, IPs discovered
  endpoints      – URLs, API routes
  parameters     – discovered parameters per endpoint
  dns_records    – DNS resolution results
  technologies   – tech stack detected per target
  vulnerabilities – findings (from LLM + header analysis)
  llm_chunks     – every LLM chunk sent + response (full audit)
  llm_analyses   – merged per-file LLM analysis text
  action_log     – every action taken (audit trail)
"""

import json
import logging
import sqlite3
import uuid
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import BASE_DIR, DATA_DIR, TARGET_DOMAIN

# ── Database path ───────────────────────────────────────────
DB_PATH = DATA_DIR / "bbhunter.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uid() -> str:
    return str(uuid.uuid4())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Database Connection & Schema
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SCHEMA = """
-- Targets (authorized domains)
CREATE TABLE IF NOT EXISTS targets (
    id            TEXT PRIMARY KEY,
    domain        TEXT NOT NULL UNIQUE,
    program       TEXT DEFAULT '',
    platform      TEXT DEFAULT '',
    scope_json    TEXT DEFAULT '{}',
    authorization_json TEXT DEFAULT '{}',
    rules_json    TEXT DEFAULT '{}',
    created_at    TEXT NOT NULL
);

-- Scans (each pipeline execution)
CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_type     TEXT DEFAULT 'passive_recon',
    status        TEXT DEFAULT 'running',
    started_at    TEXT,
    completed_at  TEXT,
    assets_found  INTEGER DEFAULT 0,
    endpoints_found INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    errors_json   TEXT DEFAULT '[]',
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Assets (subdomains, IPs)
CREATE TABLE IF NOT EXISTS assets (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_id       TEXT DEFAULT '',
    asset_type    TEXT NOT NULL,
    value         TEXT NOT NULL,
    source        TEXT DEFAULT '',
    in_scope      INTEGER DEFAULT 1,
    metadata_json TEXT DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id),
    FOREIGN KEY (scan_id)   REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_value ON assets(value);

-- Endpoints (URLs, API routes)
CREATE TABLE IF NOT EXISTS endpoints (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_id       TEXT DEFAULT '',
    url           TEXT NOT NULL,
    method        TEXT DEFAULT 'GET',
    status_code   INTEGER DEFAULT 0,
    content_type  TEXT DEFAULT '',
    source        TEXT DEFAULT '',
    is_interesting INTEGER DEFAULT 0,
    category      TEXT DEFAULT '',
    parameters_json TEXT DEFAULT '[]',
    headers_json  TEXT DEFAULT '{}',
    auth_required INTEGER DEFAULT 0,
    technology_json TEXT DEFAULT '[]',
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_url ON endpoints(url);

-- Parameters
CREATE TABLE IF NOT EXISTS parameters (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    endpoint_id   TEXT DEFAULT '',
    name          TEXT NOT NULL,
    location      TEXT DEFAULT 'query',
    sample_urls   TEXT DEFAULT '[]',
    is_interesting INTEGER DEFAULT 0,
    metadata_json TEXT DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE INDEX IF NOT EXISTS idx_params_name ON parameters(name);

-- DNS Records
CREATE TABLE IF NOT EXISTS dns_records (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_id       TEXT DEFAULT '',
    subdomain     TEXT NOT NULL,
    record_type   TEXT DEFAULT '',
    value         TEXT DEFAULT '',
    raw_line      TEXT DEFAULT '',
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Technologies detected
CREATE TABLE IF NOT EXISTS technologies (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_id       TEXT DEFAULT '',
    url           TEXT NOT NULL,
    header_name   TEXT DEFAULT '',
    header_value  TEXT DEFAULT '',
    tech_name     TEXT DEFAULT '',
    raw_headers   TEXT DEFAULT '',
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Vulnerabilities / Findings
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_id       TEXT DEFAULT '',
    title         TEXT NOT NULL,
    category      TEXT DEFAULT 'other',
    severity      TEXT DEFAULT 'info',
    description   TEXT DEFAULT '',
    url           TEXT DEFAULT '',
    parameter     TEXT DEFAULT '',
    payload       TEXT DEFAULT '',
    evidence      TEXT DEFAULT '',
    request       TEXT DEFAULT '',
    response      TEXT DEFAULT '',
    errors_json    TEXT DEFAULT '[]',
    impact        TEXT DEFAULT '',
    remediation   TEXT DEFAULT '',
    next_steps    TEXT DEFAULT '',
    confidence    REAL DEFAULT 0.0,
    source        TEXT DEFAULT 'llm_analysis',
    cvss_score    REAL DEFAULT 0.0,
    is_verified   INTEGER DEFAULT 0,
    false_positive INTEGER DEFAULT 0,
    chain_ids_json TEXT DEFAULT '[]',
    metadata_json TEXT DEFAULT '{}',
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_category ON vulnerabilities(category);

-- Exploit Chains
CREATE TABLE IF NOT EXISTS exploit_chains (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT DEFAULT '',
    vulnerability_ids_json TEXT DEFAULT '[]',
    combined_severity TEXT DEFAULT 'high',
    impact        TEXT DEFAULT '',
    attack_path_json TEXT DEFAULT '[]',
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Feedback
CREATE TABLE IF NOT EXISTS feedback (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT,
    is_true_positive INTEGER,
    researcher_notes TEXT DEFAULT '',
    created_at    TEXT NOT NULL
);

-- LLM Chunks (audit trail of every chunk sent to LLM)
CREATE TABLE IF NOT EXISTS llm_chunks (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_id       TEXT DEFAULT '',
    source_file   TEXT NOT NULL,
    chunk_index   INTEGER NOT NULL,
    total_chunks  INTEGER DEFAULT 0,
    chunk_hash    TEXT DEFAULT '',
    chunk_chars   INTEGER DEFAULT 0,
    chunk_lines   INTEGER DEFAULT 0,
    prompt_text   TEXT DEFAULT '',
    response_text TEXT DEFAULT '',
    tokens_prompt INTEGER DEFAULT 0,
    tokens_eval   INTEGER DEFAULT 0,
    duration_s    REAL DEFAULT 0.0,
    success       INTEGER DEFAULT 0,
    error         TEXT DEFAULT '',
    llm_model     TEXT DEFAULT '',
    created_at    TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE INDEX IF NOT EXISTS idx_llm_file ON llm_chunks(source_file);

-- LLM Analyses (merged per-file analysis)
CREATE TABLE IF NOT EXISTS llm_analyses (
    id            TEXT PRIMARY KEY,
    target_id     TEXT NOT NULL,
    scan_id       TEXT DEFAULT '',
    source_file   TEXT NOT NULL,
    merged_text   TEXT DEFAULT '',
    chunks_total  INTEGER DEFAULT 0,
    chunks_done   INTEGER DEFAULT 0,
    total_tokens  INTEGER DEFAULT 0,
    total_duration_s REAL DEFAULT 0.0,
    created_at    TEXT NOT NULL,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

-- Action Log (audit trail)
CREATE TABLE IF NOT EXISTS action_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT DEFAULT '',
    step_name     TEXT DEFAULT '',
    tool_name     TEXT DEFAULT '',
    details_json  TEXT DEFAULT '{}',
    level         TEXT DEFAULT 'INFO',
    scan_id       TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_actions_ts ON action_log(timestamp);
"""


class DBManager:
    """Synchronous SQLite manager for the BBHunter pipeline."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._init_schema()

    def _connect(self):
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def _init_schema(self):
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        if self.conn:
            self.conn.close()

    # ── Helper ──────────────────────────────────────────────
    def _exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self.conn.execute(sql, params)

    def _exec_many(self, sql: str, params_list: list[tuple]):
        self.conn.executemany(sql, params_list)
        self.conn.commit()

    def _fetch_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def _fetch_all(self, sql: str, params: tuple = ()) -> list[dict]:
        rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Targets
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def upsert_target(self, domain: str, program: str = "",
                      platform: str = "", scope: dict = None,
                      rules: dict = None) -> str:
        """Create or update a target. Returns target_id."""
        existing = self._fetch_one(
            "SELECT id FROM targets WHERE domain = ?", (domain,))
        if existing:
            self._exec("""UPDATE targets SET program=?, platform=?,
                          scope_json=?, rules_json=? WHERE domain=?""",
                       (program, platform, json.dumps(scope or {}),
                        json.dumps(rules or {}), domain))
            self.conn.commit()
            return existing["id"]

        tid = _uid()
        self._exec("""INSERT INTO targets
            (id, domain, program, platform, scope_json, rules_json, created_at)
            VALUES (?,?,?,?,?,?,?)""",
                   (tid, domain, program, platform,
                    json.dumps(scope or {}), json.dumps(rules or {}), _now()))
        self.conn.commit()
        return tid

    def get_target_id(self, domain: str) -> Optional[str]:
        row = self._fetch_one("SELECT id FROM targets WHERE domain = ?", (domain,))
        return row["id"] if row else None

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Scan Runs
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def start_scan(self, target_id: str, scan_type: str = "passive_recon") -> str:
        """Start a new scan run. Returns scan_id."""
        rid = _uid()
        self._exec("""INSERT INTO scans
            (id, target_id, scan_type, status, started_at)
            VALUES (?,?,?,?,?)""",
                   (rid, target_id, scan_type, "running", _now()))
        self.conn.commit()
        return rid

    def update_scan(self, run_id: str, status: str = "completed",
                        steps: list = None, stats: dict = None):
        self._exec("""UPDATE scans SET status=?, errors_json=?,
                      metadata_json=?, completed_at=? WHERE id=?""",
                   (status, json.dumps(steps or []),
                    json.dumps(stats or {}), _now(), run_id))
        self.conn.commit()

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Assets (Subdomains, IPs)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_assets(self, target_id: str, scan_id: str,
                     assets: list[dict]) -> int:
        """
        Bulk-insert assets. Each dict: {type, value, source, in_scope, metadata}
        Skips duplicates (same target+value).
        Returns count inserted.
        """
        inserted = 0
        for a in assets:
            existing = self._fetch_one(
                "SELECT id FROM assets WHERE target_id=? AND value=?",
                (target_id, a["value"]))
            if existing:
                continue
            self._exec("""INSERT INTO assets
                (id, target_id, scan_id, asset_type, value, source,
                 in_scope, metadata_json, discovered_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                       (_uid(), target_id, scan_id,
                        a.get("type", "subdomain"), a["value"],
                        a.get("source", ""), a.get("in_scope", 1),
                        json.dumps(a.get("metadata", {})), _now()))
            inserted += 1
        self.conn.commit()
        return inserted

    def get_assets(self, target_id: str, asset_type: str = None) -> list[dict]:
        if asset_type:
            return self._fetch_all(
                "SELECT * FROM assets WHERE target_id=? AND asset_type=?",
                (target_id, asset_type))
        return self._fetch_all(
            "SELECT * FROM assets WHERE target_id=?", (target_id,))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Endpoints (URLs)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_endpoints(self, target_id: str, scan_id: str,
                        endpoints: list[dict]) -> int:
        """
        Bulk-insert endpoints. Each dict: {url, source, is_interesting, category}
        Skips duplicates (same target+url).
        """
        inserted = 0
        for ep in endpoints:
            existing = self._fetch_one(
                "SELECT id FROM endpoints WHERE target_id=? AND url=?",
                (target_id, ep["url"]))
            if existing:
                continue
            self._exec("""INSERT INTO endpoints
                (id, target_id, scan_id, url, method, source,
                 is_interesting, category, metadata_json, discovered_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                       (_uid(), target_id, scan_id,
                        ep["url"], ep.get("method", "GET"),
                        ep.get("source", ""),
                        ep.get("is_interesting", 0),
                        ep.get("category", ""),
                        json.dumps(ep.get("metadata", {})), _now()))
            inserted += 1
        self.conn.commit()
        return inserted

    def get_endpoints(self, target_id: str, interesting_only: bool = False) -> list[dict]:
        if interesting_only:
            return self._fetch_all(
                "SELECT * FROM endpoints WHERE target_id=? AND is_interesting=1",
                (target_id,))
        return self._fetch_all(
            "SELECT * FROM endpoints WHERE target_id=?", (target_id,))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Parameters
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_parameters(self, target_id: str, scan_id: str,
                         params: list[dict]) -> int:
        """Store discovered parameters. Each: {name, location, sample_urls, is_interesting}"""
        inserted = 0
        for p in params:
            existing = self._fetch_one(
                "SELECT id FROM parameters WHERE target_id=? AND name=?",
                (target_id, p["name"]))
            if existing:
                continue
            self._exec("""INSERT INTO parameters
                (id, target_id, endpoint_id, name, location, sample_urls,
                 is_interesting, metadata_json, discovered_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                       (_uid(), target_id, p.get("endpoint_id", ""),
                        p["name"], p.get("location", "query"),
                        json.dumps(p.get("sample_urls", [])),
                        p.get("is_interesting", 0),
                        json.dumps(p.get("metadata", {})), _now()))
            inserted += 1
        self.conn.commit()
        return inserted

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  DNS Records
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_dns_records(self, target_id: str, scan_id: str,
                          records: list[dict]) -> int:
        """Store DNS records. Each: {subdomain, record_type, value, raw_line}"""
        inserted = 0
        for r in records:
            self._exec("""INSERT INTO dns_records
                (id, target_id, scan_id, subdomain, record_type, value,
                 raw_line, discovered_at)
                VALUES (?,?,?,?,?,?,?,?)""",
                       (_uid(), target_id, scan_id,
                        r.get("subdomain", ""), r.get("record_type", ""),
                        r.get("value", ""), r.get("raw_line", ""), _now()))
            inserted += 1
        self.conn.commit()
        return inserted

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Technologies
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_technologies(self, target_id: str, scan_id: str,
                           techs: list[dict]) -> int:
        """Store tech detection results."""
        inserted = 0
        for t in techs:
            self._exec("""INSERT INTO technologies
                (id, target_id, scan_id, url, header_name, header_value,
                 tech_name, raw_headers, discovered_at)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                       (_uid(), target_id, scan_id,
                        t.get("url", ""), t.get("header_name", ""),
                        t.get("header_value", ""), t.get("tech_name", ""),
                        t.get("raw_headers", ""), _now()))
            inserted += 1
        self.conn.commit()
        return inserted

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Vulnerabilities / Findings
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_vulnerability(self, target_id: str, scan_id: str,
                            vuln: dict) -> str:
        """Store a single vulnerability/finding. Returns vuln_id."""
        vid = _uid()
        self._exec("""INSERT INTO vulnerabilities
            (id, target_id, scan_id, title, category, severity,
             description, url, parameter, evidence, impact, remediation,
             next_steps, confidence, source, cvss_score, metadata_json, discovered_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (vid, target_id, scan_id,
                    vuln.get("title", "Untitled"),
                    vuln.get("category", "other"),
                    vuln.get("severity", "info").lower(),
                    vuln.get("description", ""),
                    vuln.get("url", ""),
                    vuln.get("parameter", ""),
                    vuln.get("evidence", ""),
                    vuln.get("impact", ""),
                    vuln.get("remediation", ""),
                    vuln.get("next_steps", ""),
                    vuln.get("confidence", 0.0),
                    vuln.get("source", "llm_analysis"),
                    vuln.get("cvss_score", 0.0),
                    json.dumps(vuln.get("metadata", {})), _now()))
        self.conn.commit()
        return vid

    def store_vulnerabilities(self, target_id: str, scan_id: str,
                              vulns: list[dict]) -> int:
        """Bulk-store vulnerabilities."""
        count = 0
        for v in vulns:
            self.store_vulnerability(target_id, scan_id, v)
            count += 1
        return count

    def get_vulnerabilities(self, target_id: str,
                            severity: str = None) -> list[dict]:
        if severity:
            return self._fetch_all(
                "SELECT * FROM vulnerabilities WHERE target_id=? AND severity=? ORDER BY discovered_at DESC",
                (target_id, severity.lower()))
        return self._fetch_all(
            "SELECT * FROM vulnerabilities WHERE target_id=? ORDER BY discovered_at DESC",
            (target_id,))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  LLM Chunks (audit)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_llm_chunk(self, target_id: str, scan_id: str,
                        chunk_data: dict) -> str:
        """Store a single LLM chunk interaction."""
        cid = _uid()
        self._exec("""INSERT INTO llm_chunks
            (id, target_id, scan_id, source_file, chunk_index,
             total_chunks, chunk_hash, chunk_chars, chunk_lines,
             prompt_text, response_text, tokens_prompt, tokens_eval,
             duration_s, success, error, llm_model, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                   (cid, target_id, scan_id,
                    chunk_data.get("source_file", ""),
                    chunk_data.get("chunk_index", 0),
                    chunk_data.get("total_chunks", 0),
                    chunk_data.get("chunk_hash", ""),
                    chunk_data.get("chunk_chars", 0),
                    chunk_data.get("chunk_lines", 0),
                    chunk_data.get("prompt_text", ""),
                    chunk_data.get("response_text", ""),
                    chunk_data.get("tokens_prompt", 0),
                    chunk_data.get("tokens_eval", 0),
                    chunk_data.get("duration_s", 0.0),
                    1 if chunk_data.get("success") else 0,
                    chunk_data.get("error", ""),
                    chunk_data.get("llm_model", ""),
                    _now()))
        self.conn.commit()
        return cid

    def get_llm_chunks(self, target_id: str, source_file: str = None) -> list[dict]:
        if source_file:
            return self._fetch_all(
                "SELECT * FROM llm_chunks WHERE target_id=? AND source_file=? ORDER BY chunk_index",
                (target_id, source_file))
        return self._fetch_all(
            "SELECT * FROM llm_chunks WHERE target_id=? ORDER BY source_file, chunk_index",
            (target_id,))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  LLM Analyses (merged)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def store_llm_analysis(self, target_id: str, scan_id: str,
                           analysis: dict) -> str:
        """Store merged per-file LLM analysis."""
        aid = _uid()
        self._exec("""INSERT INTO llm_analyses
            (id, target_id, scan_id, source_file, merged_text,
             chunks_total, chunks_done, total_tokens, total_duration_s, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
                   (aid, target_id, scan_id,
                    analysis.get("source_file", ""),
                    analysis.get("merged_text", ""),
                    analysis.get("chunks_total", 0),
                    analysis.get("chunks_done", 0),
                    analysis.get("total_tokens", 0),
                    analysis.get("total_duration_s", 0.0),
                    _now()))
        self.conn.commit()
        return aid

    def get_llm_analyses(self, target_id: str) -> list[dict]:
        return self._fetch_all(
            "SELECT * FROM llm_analyses WHERE target_id=? ORDER BY created_at",
            (target_id,))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Action Log (Audit Trail)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def log_action(self, action: str, target: str = "",
                   step_name: str = "", tool_name: str = "",
                   details: dict = None, level: str = "INFO",
                   scan_id: str = ""):
        """Log an action to the audit trail."""
        self._exec("""INSERT INTO action_log
            (timestamp, action, target, step_name, tool_name,
             details_json, level, scan_id)
            VALUES (?,?,?,?,?,?,?,?)""",
                   (_now(), action, target, step_name, tool_name,
                    json.dumps(details or {}), level, scan_id))
        self.conn.commit()

    def get_action_log(self, scan_id: str = None,
                       limit: int = 100) -> list[dict]:
        if scan_id:
            return self._fetch_all(
                "SELECT * FROM action_log WHERE scan_id=? ORDER BY timestamp DESC LIMIT ?",
                (scan_id, limit))
        return self._fetch_all(
            "SELECT * FROM action_log ORDER BY timestamp DESC LIMIT ?",
            (limit,))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  Stats / Queries
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def get_stats(self, target_id: str) -> dict:
        """Get aggregate stats for a target."""
        stats = {}
        for table in ["assets", "endpoints", "parameters", "dns_records",
                       "technologies", "vulnerabilities", "llm_chunks", "llm_analyses"]:
            row = self._fetch_one(
                f"SELECT COUNT(*) as cnt FROM {table} WHERE target_id=?",
                (target_id,))
            stats[table] = row["cnt"] if row else 0

        # Vulnerability severity breakdown
        vulns = self._fetch_all(
            """SELECT severity, COUNT(*) as cnt FROM vulnerabilities
               WHERE target_id=? GROUP BY severity""", (target_id,))
        stats["vuln_by_severity"] = {v["severity"]: v["cnt"] for v in vulns}

        # Action log count
        row = self._fetch_one("SELECT COUNT(*) as cnt FROM action_log")
        stats["action_log"] = row["cnt"] if row else 0

        return stats

    def get_all_findings_text(self, target_id: str) -> str:
        """Get all merged LLM analyses concatenated for report generation."""
        analyses = self.get_llm_analyses(target_id)
        parts = []
        for a in analyses:
            if a.get("merged_text"):
                parts.append(f"\n{'='*50}\nSource: {a['source_file']}\n{'='*50}")
                parts.append(a["merged_text"])
        return "\n".join(parts)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Safety Gate (scope enforcement)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SafetyChecker:
    """
    Safety gate for scope enforcement.
    Delegates to bbhunter.safety.SafetyGate when available, falls back to
    local rule checking so scripts work even when bbhunter is not installed.
    """

    def __init__(self, rules: dict):
        self.rules = rules
        self.oos_domains = set(rules.get("out_of_scope_domains", []))
        self.oos_wildcards = rules.get("out_of_scope_wildcards", [])
        self.oos_paths = rules.get("out_of_scope_paths", [])

        # Try to reuse the unified SafetyGate
        self._gate = None
        try:
            from bbhunter.safety import get_safety_gate
            self._gate = get_safety_gate()
        except Exception as exc:
            logging.debug(f"Failed to load safety gate: {exc}")

    def is_in_scope(self, domain_or_url: str) -> bool:
        """Check if a domain/URL is in scope."""
        # Prefer unified gate when available
        if self._gate is not None:
            return self._gate.is_in_scope(domain_or_url)

        return self._local_check(domain_or_url)

    def _local_check(self, domain_or_url: str) -> bool:
        """Fallback local scope check using rules dict."""
        domain = domain_or_url
        path = ""
        if "://" in domain_or_url:
            parts = domain_or_url.split("://", 1)[1]
            domain = parts.split("/")[0].split(":")[0]
            path = "/" + "/".join(parts.split("/")[1:]) if "/" in parts else ""

        # Check out-of-scope domains
        if domain in self.oos_domains:
            return False

        # Check wildcards
        for wc in self.oos_wildcards:
            pattern = wc.replace("*.", "")
            if domain.endswith(pattern):
                return False

        # Check paths
        for p in self.oos_paths:
            pattern = p.replace("*", "")
            if pattern and pattern in path:
                return False

        return True

    def check_or_raise(self, domain_or_url: str, action: str = ""):
        """Raise if out of scope."""
        if not self.is_in_scope(domain_or_url):
            raise PermissionError(
                f"BLOCKED: {domain_or_url} is OUT OF SCOPE. Action: {action}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Finding Parser (extract structured vulns from LLM text)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_llm_findings(llm_text: str) -> list[dict]:
    """
    Parse structured findings from LLM analysis text.
    Looks for patterns like:
      - **Finding**: ...  / **Severity**: ... / **Why interesting**: ...
      - ---FINDING--- / Title: / Severity: / ---END---
      - Bullet points with severity markers
    Returns list of vulnerability dicts.
    """
    import re
    findings = []

    # Pattern 1: ---FINDING--- blocks (from generate_report.py extract prompt)
    finding_blocks = re.split(r'---FINDING---', llm_text)
    for block in finding_blocks[1:]:  # skip first (before any ---FINDING---)
        end_idx = block.find("---END---")
        if end_idx > 0:
            block = block[:end_idx]

        vuln = _parse_finding_block(block)
        if vuln.get("title"):
            findings.append(vuln)

    # Pattern 2: Numbered findings with **Finding** markers
    if not findings:
        numbered = re.split(r'\n\d+\.\s+\*\*Finding\*\*:', llm_text)
        for block in numbered[1:]:
            vuln = _parse_markdown_finding(block)
            if vuln.get("title"):
                findings.append(vuln)

    # Pattern 3: **Finding**: lines
    if not findings:
        for match in re.finditer(
            r'\*\*Finding\*\*:\s*(.+?)(?:\n\*\*|$)', llm_text, re.DOTALL):
            title = match.group(1).strip().split("\n")[0]
            if title:
                findings.append({"title": title, "severity": "info"})

    return findings


def _parse_finding_block(block: str) -> dict:
    """Parse a ---FINDING--- block into a vuln dict."""
    vuln = {}
    field_map = {
        "title": "title", "severity": "severity", "category": "category",
        "description": "description", "evidence": "evidence",
        "impact": "impact", "next steps": "next_steps",
        "remediation": "remediation", "url": "url", "parameter": "parameter",
    }
    for line in block.strip().splitlines():
        line = line.strip()
        for key, field in field_map.items():
            if line.lower().startswith(key + ":"):
                vuln[field] = line.split(":", 1)[1].strip()
                break
    return vuln


def _parse_markdown_finding(block: str) -> dict:
    """Parse a markdown-style finding block."""
    vuln = {}
    lines = block.strip().splitlines()
    if lines:
        vuln["title"] = lines[0].strip()
    for line in lines:
        line_lower = line.lower().strip()
        if "severity" in line_lower:
            for sev in ["critical", "high", "medium", "low", "info"]:
                if sev in line_lower:
                    vuln["severity"] = sev
                    break
        if "why interesting" in line_lower or "implication" in line_lower:
            vuln["description"] = line.split(":", 1)[-1].strip() if ":" in line else ""
        if "next step" in line_lower:
            vuln["next_steps"] = line.split(":", 1)[-1].strip() if ":" in line else ""
        if "url" in line_lower or "link" in line_lower or "endpoint" in line_lower:
            val = line.split(":", 1)[-1].strip() if ":" in line else ""
            # Handle **URL/Link**: format
            val = val.lstrip("*").strip()
            if val:
                vuln["url"] = val
    return vuln


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Singleton access
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_db: Optional[DBManager] = None

def get_db() -> DBManager:
    """Get the singleton database manager."""
    global _db
    if _db is None:
        _db = DBManager()
    return _db


if __name__ == "__main__":
    # Quick test
    db = DBManager()
    print(f"✅ Database created: {DB_PATH}")
    print(f"   Size: {DB_PATH.stat().st_size:,} bytes")

    # Check tables
    tables = db._fetch_all(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    print(f"   Tables: {', '.join(t['name'] for t in tables)}")
    db.close()
    print("✅ All tables ready!")

"""
BBHunter Automation Pipeline - Configuration
=============================================
Single source of truth: delegates to bbhunter.config (loads config.yaml).
All scripts import from here for backward compatibility.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Ensure bbhunter package is importable ────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# ── Load unified config from config.yaml ─────────────────────
from bbhunter.config import get_config, load_config, Config  # noqa: E402

_CONFIG_PATH = BASE_DIR / "config.yaml"

# Force-load config if not yet loaded
import bbhunter.config as _bb_cfg  # noqa: E402
if _bb_cfg._config is None:
    try:
        _bb_cfg._config = load_config(str(_CONFIG_PATH))
    except FileNotFoundError:
        _bb_cfg._config = Config()

_cfg = get_config()

# ── Paths (derived from unified config + BASE_DIR) ───────────
DATA_DIR = BASE_DIR / _cfg.pipeline.data_dir.lstrip("./")
REPORTS_DIR = BASE_DIR / _cfg.pipeline.reports_dir.lstrip("./")
LOGS_DIR = BASE_DIR / _cfg.pipeline.logs_dir.lstrip("./")
LLM_OUTPUT_DIR = BASE_DIR / _cfg.pipeline.llm_output_dir.lstrip("./")

# ── Target ───────────────────────────────────────────────────
# Environment variable overrides config.yaml
TARGET_DOMAIN = os.getenv("BB_TARGET") or _cfg.pipeline.target_domain or "doordash.com"
PROGRAM_NAME = os.getenv("BB_PROGRAM") or _cfg.pipeline.program_name or "Unknown Program"
TARGET_DIR = DATA_DIR / TARGET_DOMAIN.replace(".", "_")
TARGET_LLM_DIR = LLM_OUTPUT_DIR / TARGET_DOMAIN.replace(".", "_")
TARGET_REPORT_DIR = REPORTS_DIR / TARGET_DOMAIN.replace(".", "_")

# ── Tool paths (Go tools in ~/go/bin) ────────────────────────
GO_BIN = Path.home() / "go" / "bin"
TOOLS = {
    "subfinder":    GO_BIN / "subfinder",
    "amass":        GO_BIN / "amass",
    "httpx":        GO_BIN / "httpx",
    "gau":          GO_BIN / "gau",
    "waybackurls":  GO_BIN / "waybackurls",
    "katana":       GO_BIN / "katana",
    "hakrawler":    GO_BIN / "hakrawler",
    "dnsx":         GO_BIN / "dnsx",
    "nmap":         Path("/usr/bin/nmap"),
    "dig":          Path("/usr/bin/dig"),
    "curl":         Path("/usr/bin/curl"),
    "whois":        Path("/usr/bin/whois"),
}

# ── LLM Configuration (from unified config.yaml) ─────────────
LLM_API_URL = os.getenv("LLM_API_URL") or _cfg.llm.api_url
LLM_MODEL = os.getenv("LLM_MODEL") or _cfg.llm.model
CHUNK_SIZE_CHARS = _cfg.llm.chunk_size_chars
CHUNK_OVERLAP_CHARS = _cfg.llm.chunk_overlap_chars
MAX_RESPONSE_TOKENS = _cfg.llm.max_response_tokens
LLM_TEMPERATURE = _cfg.llm.temperature
LLM_REQUEST_TIMEOUT = _cfg.llm.request_timeout
LLM_NUM_CTX = _cfg.llm.num_ctx
LLM_NUM_BATCH = _cfg.llm.num_batch

# ── Target-Specific Rules (from unified config.yaml) ─────────
DOORDASH_RULES = {
    "no_automated_scanners": _cfg.target_rules.no_automated_scanners,
    "no_brute_force": _cfg.target_rules.no_brute_force,
    "no_dos": _cfg.target_rules.no_dos,
    "required_header": _cfg.target_rules.required_header,
    "in_scope": list(_cfg.target_rules.in_scope),
    "out_of_scope_domains": list(_cfg.target_rules.out_of_scope_domains),
    "out_of_scope_wildcards": list(_cfg.target_rules.out_of_scope_wildcards),
    "out_of_scope_paths": list(_cfg.target_rules.out_of_scope_paths),
}

# ── Timeout / Skip Configuration ─────────────────────────────
STEP_TIMEOUT = int(os.getenv("BB_STEP_TIMEOUT") or _cfg.pipeline.step_timeout or 600)
LLM_CHUNK_TIMEOUT = int(os.getenv("BB_CHUNK_TIMEOUT") or _cfg.pipeline.llm_chunk_timeout or 300)
MAX_CONSECUTIVE_FAILURES = int(
    os.getenv("BB_MAX_FAILURES") or _cfg.pipeline.max_consecutive_failures or 3
)

# ── Recon Pipeline Steps ─────────────────────────────────────
RECON_STEPS = [
    "subdomain_enum",
    "amass_enum",
    "dns_resolution",
    "httpx_probe",
    "url_discovery",
    "wayback_urls",
    "katana_crawl",
    "hakrawler",
    "tech_detection",
    "port_scan_passive",
    "js_analysis",
    "param_discovery",
    "header_analysis",
    "scope_filter",
]


def ensure_dirs():
    """Create all necessary output directories."""
    for d in [TARGET_DIR, TARGET_LLM_DIR, TARGET_REPORT_DIR, LOGS_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def reload_target(target: str):
    """
    Reload configuration for a different target domain.
    Call this when --target changes at runtime.
    """
    global TARGET_DOMAIN, TARGET_DIR, TARGET_LLM_DIR, TARGET_REPORT_DIR
    os.environ["BB_TARGET"] = target
    TARGET_DOMAIN = target
    TARGET_DIR = DATA_DIR / target.replace(".", "_")
    TARGET_LLM_DIR = LLM_OUTPUT_DIR / target.replace(".", "_")
    TARGET_REPORT_DIR = REPORTS_DIR / target.replace(".", "_")

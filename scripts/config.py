"""
BBHunter Automation Pipeline - Configuration
=============================================
Central config for the recon automation + LLM analysis pipeline.
"""

import os
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
LLM_OUTPUT_DIR = BASE_DIR / "llm_analysis"

# ── Target ───────────────────────────────────────────────────
TARGET_DOMAIN = os.getenv("BB_TARGET", "doordash.com")
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

# ── LLM Configuration ────────────────────────────────────────
# Ollama with dolphin-llama3:8b (4.7GB, fits GTX 1650 4GB VRAM)
# dolphin = uncensored, no thinking overhead, direct responses
LLM_API_URL = os.getenv("LLM_API_URL", "http://localhost:11434")
LLM_MODEL = os.getenv("LLM_MODEL", "dolphin-llama3:8b")

# Chunking — dolphin-llama3 supports 8K context, no thinking waste
# So we can use bigger chunks and longer responses than qwen3.5
CHUNK_SIZE_CHARS = 3000          # ~750 tokens per chunk
CHUNK_OVERLAP_CHARS = 200        # overlap to avoid cutting context
MAX_RESPONSE_TOKENS = 2048       # max tokens in LLM response
LLM_TEMPERATURE = 0.3            # low temp for analytical tasks
LLM_REQUEST_TIMEOUT = 300        # 5 min timeout per chunk

# ── DoorDash Specific Rules ──────────────────────────────────
DOORDASH_RULES = {
    "no_automated_scanners": True,
    "no_brute_force": True,
    "no_dos": True,
    "required_header": "X-Bug-Bounty: researcher-handle",
    "in_scope": [
        "www.doordash.com",
        "doordash.com",
    ],
    "out_of_scope_domains": [
        "unified-gateway.doordash.com",
        "track.doordash.com",
        "merchant-portal.doordash.com",
        "merchant-mobile-bff.doordash.com",
        "ir.doordash.com",
        "internal.doordash.com",
        "consumer-mobile-bff.doordash.com",
        "careersatdoordash.com",
        "help.doordash.com",
    ],
    "out_of_scope_wildcards": [
        "*.order.online",
        "*.doorcrawl.com",
        "*.dashapi.com",
    ],
    "out_of_scope_paths": [
        "/merchant/*",
        "/unified-gateway/*",
        "/orders/drive/*",
    ],
}

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

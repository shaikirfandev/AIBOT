"""
Core configuration loader for BugBounty Hunter Suite.
Loads config.yaml and validates all settings.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


# ---------------------------------------------------------------------------
# Pydantic models for typed configuration
# ---------------------------------------------------------------------------

class SafetyConfig(BaseModel):
    require_authorization: bool = True
    authorization_file: str = "./authorized_targets.yaml"
    rate_limit_rps: int = 10
    max_requests_per_target: int = 10_000
    respect_robots_txt: bool = True
    avoid_dos: bool = True
    log_all_actions: bool = True
    action_log_file: str = "./logs/actions.log"
    banned_methods: list[str] = Field(default_factory=lambda: ["dos", "ddos", "brute_force_production"])


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./data/bbhunter.db"
    echo: bool = False


class ReconPassiveConfig(BaseModel):
    enable_ct_logs: bool = True
    enable_wayback: bool = True
    enable_github_search: bool = True
    enable_shodan: bool = False
    enable_censys: bool = False
    enable_virustotal: bool = False


class ReconActiveConfig(BaseModel):
    enable_dns_brute: bool = True
    enable_port_scan: bool = False
    dns_wordlist: str = "./wordlists/dns-subdomains.txt"
    dns_resolvers: list[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1", "9.9.9.9"])


class ReconConfig(BaseModel):
    passive: ReconPassiveConfig = ReconPassiveConfig()
    active: ReconActiveConfig = ReconActiveConfig()
    timeout: int = 30
    max_concurrent: int = 20


class SurfaceMappingConfig(BaseModel):
    crawl_depth: int = 3
    max_urls: int = 5000
    js_analysis: bool = True
    discover_graphql: bool = True
    discover_swagger: bool = True
    technology_fingerprint: bool = True
    waf_detection: bool = True
    timeout: int = 15


class ScannerConfig(BaseModel):
    categories: list[str] = Field(default_factory=list)
    advanced: list[str] = Field(default_factory=list)
    max_payloads_per_param: int = 50
    timeout: int = 20
    follow_redirects: bool = False


class PayloadConfig(BaseModel):
    mutation_level: int = 3
    waf_bypass: bool = True
    encoding_layers: int = 3
    custom_payloads_dir: str = "./payloads/custom"


class AnalysisConfig(BaseModel):
    false_positive_threshold: float = 0.7
    chain_detection: bool = True
    impact_scoring: bool = True
    auto_verify: bool = True


class ReportingConfig(BaseModel):
    format: str = "markdown"
    template: str = "hackerone"
    include_screenshots: bool = True
    include_payloads: bool = True
    auto_severity: bool = True


class DashboardConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8443
    secret_key: str = "CHANGE-ME-IN-PRODUCTION"
    enable_auth: bool = True
    default_user: str = "admin"


class LearningConfig(BaseModel):
    enable: bool = True
    feedback_db: str = "./data/feedback.db"
    retrain_interval_hours: int = 24
    min_samples: int = 100


class APIKeysConfig(BaseModel):
    shodan: str = ""
    censys_id: str = ""
    censys_secret: str = ""
    virustotal: str = ""
    github_token: str = ""


class LLMConfig(BaseModel):
    """Local LLM (Ollama) configuration."""
    api_url: str = "http://localhost:11434"
    model: str = "dolphin-llama3:8b"
    chunk_size_chars: int = 3000
    chunk_overlap_chars: int = 200
    max_response_tokens: int = 2048
    temperature: float = 0.3
    request_timeout: int = 300
    num_ctx: int = 4096
    num_batch: int = 256


class TargetRules(BaseModel):
    """Per-target program rules (e.g., DoorDash HackerOne rules)."""
    no_automated_scanners: bool = False
    no_brute_force: bool = False
    no_dos: bool = False
    required_header: str = ""
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope_domains: list[str] = Field(default_factory=list)
    out_of_scope_wildcards: list[str] = Field(default_factory=list)
    out_of_scope_paths: list[str] = Field(default_factory=list)


class PipelineConfig(BaseModel):
    """Pipeline orchestration settings."""
    target_domain: str = ""
    program_name: str = ""
    data_dir: str = "./data"
    llm_output_dir: str = "./llm_analysis"
    reports_dir: str = "./reports"
    logs_dir: str = "./logs"
    step_timeout: int = 600
    llm_chunk_timeout: int = 300
    max_consecutive_failures: int = 3


class AppConfig(BaseModel):
    name: str = "BugBounty Hunter Suite"
    version: str = "1.0.0"
    log_level: str = "INFO"
    max_concurrent_tasks: int = 10
    data_dir: str = "./data"
    reports_dir: str = "./reports"


class Config(BaseModel):
    """Root configuration model."""
    app: AppConfig = AppConfig()
    safety: SafetyConfig = SafetyConfig()
    database: DatabaseConfig = DatabaseConfig()
    recon: ReconConfig = ReconConfig()
    surface_mapping: SurfaceMappingConfig = SurfaceMappingConfig()
    scanner: ScannerConfig = ScannerConfig()
    payloads: PayloadConfig = PayloadConfig()
    analysis: AnalysisConfig = AnalysisConfig()
    reporting: ReportingConfig = ReportingConfig()
    dashboard: DashboardConfig = DashboardConfig()
    learning: LearningConfig = LearningConfig()
    api_keys: APIKeysConfig = APIKeysConfig()
    llm: LLMConfig = LLMConfig()
    pipeline: PipelineConfig = PipelineConfig()
    target_rules: TargetRules = TargetRules()


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def _resolve_env_vars(data: Any) -> Any:
    """Recursively resolve ${ENV_VAR} patterns in config values."""
    if isinstance(data, str) and data.startswith("${") and data.endswith("}"):
        env_key = data[2:-1]
        return os.environ.get(env_key, "")
    if isinstance(data, dict):
        return {k: _resolve_env_vars(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_resolve_env_vars(item) for item in data]
    return data


def load_config(config_path: str | Path = "config.yaml") -> Config:
    """Load and validate configuration from YAML file."""
    config_path = Path(config_path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    raw = _resolve_env_vars(raw)
    return Config(**raw)


# Singleton config instance
_config: Config | None = None


def get_config(config_path: str | Path = "config.yaml") -> Config:
    """Get or create the singleton config instance."""
    global _config
    if _config is None:
        _config = load_config(config_path)
    return _config

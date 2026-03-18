"""
BBHunter Test Configuration & Shared Fixtures
===============================================
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Ensure the project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


# ── Reset singletons between tests ──────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_singletons():
    """Reset all module-level singletons so tests are isolated."""
    import bbhunter.config as cfg_mod
    import bbhunter.logger as log_mod
    import bbhunter.safety as safety_mod

    cfg_mod._config = None
    log_mod._logger = None
    log_mod._action_logger = None
    safety_mod._safety_gate = None
    yield
    cfg_mod._config = None
    log_mod._logger = None
    log_mod._action_logger = None
    safety_mod._safety_gate = None


# ── Temporary dirs ──────────────────────────────────────────────────────

@pytest.fixture
def tmp_data_dir(tmp_path: Path) -> Path:
    """Provide a temporary data directory."""
    d = tmp_path / "data"
    d.mkdir()
    return d


@pytest.fixture
def tmp_reports_dir(tmp_path: Path) -> Path:
    d = tmp_path / "reports"
    d.mkdir()
    return d


# ── Minimal config.yaml ────────────────────────────────────────────────

MINIMAL_CONFIG_YAML = """\
app:
  name: "BBHunter Test"
  version: "0.0.0-test"
  log_level: "DEBUG"
safety:
  require_authorization: false
database:
  url: "sqlite+aiosqlite:////:memory:"
  echo: false
dashboard:
  secret_key: "test-secret-key-do-not-use"
  enable_auth: false
  port: 8443
llm:
  api_url: "http://localhost:11434"
  model: "test-model"
  num_ctx: 2048
  num_batch: 128
pipeline:
  target_domain: "example.com"
  program_name: "Test Program"
"""


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """Write a minimal config.yaml and return its path."""
    cfg = tmp_path / "config.yaml"
    cfg.write_text(MINIMAL_CONFIG_YAML)
    return cfg


@pytest.fixture
def config(config_file: Path):
    """Load and return a Config object from the minimal YAML."""
    from bbhunter.config import load_config
    return load_config(config_file)


@pytest.fixture
def mock_config(config_file: Path):
    """Patch get_config() to return the test config globally."""
    from bbhunter.config import load_config
    cfg = load_config(config_file)
    with patch("bbhunter.config.get_config", return_value=cfg):
        yield cfg


# ── Auth targets YAML ──────────────────────────────────────────────────

AUTH_TARGETS_YAML = """\
targets:
  - domain: "example.com"
    scope:
      include:
        - "*.example.com"
      exclude:
        - "internal.example.com"
    authorization:
      type: "bug_bounty"
      platform: "Test Platform"
      expiry_date: "2099-12-31"
    rules:
      rate_limit_rps: 5
"""


@pytest.fixture
def auth_file(tmp_path: Path) -> Path:
    af = tmp_path / "authorized_targets.yaml"
    af.write_text(AUTH_TARGETS_YAML)
    return af


# ── Model factories ────────────────────────────────────────────────────

@pytest.fixture
def make_endpoint():
    """Factory for creating test Endpoint objects."""
    from bbhunter.models import Endpoint

    def _factory(**overrides) -> Endpoint:
        defaults: dict[str, Any] = {
            "target_id": "test-target-1",
            "url": "https://example.com/api/v1/users",
            "method": "GET",
        }
        defaults.update(overrides)
        return Endpoint(**defaults)

    return _factory


@pytest.fixture
def make_vulnerability():
    """Factory for creating test Vulnerability objects."""
    from bbhunter.models import Vulnerability, VulnCategory, Severity

    def _factory(**overrides) -> Vulnerability:
        defaults: dict[str, Any] = {
            "target_id": "test-target-1",
            "scan_id": "test-scan-1",
            "category": VulnCategory.XSS,
            "severity": Severity.MEDIUM,
            "title": "Test XSS Finding",
            "url": "https://example.com/search?q=test",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Reflected payload in response",
            "confidence": 0.8,
        }
        defaults.update(overrides)
        return Vulnerability(**defaults)

    return _factory


# ── Mock HTTP client ────────────────────────────────────────────────────

@pytest.fixture
def mock_httpx_client():
    """Patch httpx.AsyncClient for offline scanner tests."""
    with patch("httpx.AsyncClient") as mock_cls:
        client = MagicMock()
        mock_cls.return_value.__aenter__ = lambda s: client
        mock_cls.return_value.__aexit__ = lambda s, *a: None
        yield client

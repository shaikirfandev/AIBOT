"""Tests for bbhunter.config module."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from bbhunter.config import (
    Config,
    LLMConfig,
    PipelineConfig,
    SafetyConfig,
    DashboardConfig,
    load_config,
    get_config,
    _resolve_env_vars,
)


class TestConfigDefaults:
    """Verify default values are sensible."""

    def test_default_config_creates(self):
        cfg = Config()
        assert cfg.app.name == "BugBounty Hunter Suite"
        assert cfg.safety.require_authorization is True
        assert cfg.dashboard.port == 8443
        assert cfg.llm.num_ctx == 4096
        assert cfg.llm.num_batch == 256

    def test_pipeline_has_program_name(self):
        cfg = Config()
        assert hasattr(cfg.pipeline, "program_name")

    def test_llm_config_has_num_fields(self):
        llm = LLMConfig()
        assert llm.num_ctx > 0
        assert llm.num_batch > 0


class TestLoadConfig:
    """Test config loading from YAML."""

    def test_load_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_load_minimal_yaml(self, config_file: Path):
        cfg = load_config(config_file)
        assert cfg.app.name == "BBHunter Test"
        assert cfg.safety.require_authorization is False
        assert cfg.dashboard.secret_key == "test-secret-key-do-not-use"

    def test_singleton_returns_same_instance(self, config_file: Path):
        import bbhunter.config as mod
        mod._config = None
        c1 = get_config(config_file)
        c2 = get_config(config_file)
        assert c1 is c2

    def test_env_var_resolution(self):
        with patch.dict(os.environ, {"MY_VAR": "hello"}):
            assert _resolve_env_vars("${MY_VAR}") == "hello"

    def test_env_var_missing_returns_empty(self):
        assert _resolve_env_vars("${NONEXISTENT_VAR_XYZ}") == ""

    def test_nested_env_var_resolution(self):
        with patch.dict(os.environ, {"A": "1", "B": "2"}):
            result = _resolve_env_vars({"x": "${A}", "y": ["${B}"]})
            assert result == {"x": "1", "y": ["2"]}


class TestSafetyConfig:
    def test_banned_methods_default(self):
        sc = SafetyConfig()
        assert "dos" in sc.banned_methods
        assert "ddos" in sc.banned_methods

    def test_rate_limit_default(self):
        sc = SafetyConfig()
        assert sc.rate_limit_rps == 10


class TestDashboardConfig:
    def test_default_port_is_8443(self):
        dc = DashboardConfig()
        assert dc.port == 8443

    def test_default_secret_is_placeholder(self):
        dc = DashboardConfig()
        assert dc.secret_key == "CHANGE-ME-IN-PRODUCTION"

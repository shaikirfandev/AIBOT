"""Tests for the CLI (bbhunter.cli)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, AsyncMock

import pytest
from click.testing import CliRunner


class TestCLI:
    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_version(self, runner):
        from bbhunter.cli import main
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_help(self, runner):
        from bbhunter.cli import main
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "BBHunter" in result.output

    def test_payloads_xss(self, runner):
        from bbhunter.cli import main
        result = runner.invoke(main, ["payloads", "xss"])
        assert result.exit_code == 0
        assert "payloads generated" in result.output

    def test_learning_stats(self, runner):
        from bbhunter.cli import main
        result = runner.invoke(main, ["learning", "stats"])
        assert result.exit_code == 0

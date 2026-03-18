"""Tests for bbhunter.engines.analysis.engine (AnalysisEngine)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from bbhunter.models import Vulnerability, VulnCategory, Severity


class TestAnalysisEngine:
    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

    @pytest.mark.asyncio
    async def test_run_empty_vulns(self):
        from bbhunter.engines.analysis.engine import AnalysisEngine
        engine = AnalysisEngine()
        result = await engine.run([])
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_run_with_vulns(self, make_vulnerability):
        from bbhunter.engines.analysis.engine import AnalysisEngine
        engine = AnalysisEngine()
        vulns = [
            make_vulnerability(title="XSS 1", url="https://example.com/a"),
            make_vulnerability(title="XSS 2", url="https://example.com/b"),
        ]
        result = await engine.run(vulns)
        assert isinstance(result, dict)

    def test_cvss_estimation_exists(self):
        from bbhunter.engines.analysis.engine import estimate_cvss
        assert callable(estimate_cvss)

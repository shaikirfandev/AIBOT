"""Tests for bbhunter.engines.reporting.engine (ReportEngine)."""

from __future__ import annotations

from pathlib import Path

import pytest

from bbhunter.models import Vulnerability, VulnCategory, Severity


class TestReportEngine:
    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

    def test_generate_markdown_report(self, make_vulnerability):
        from bbhunter.engines.reporting.engine import ReportEngine
        engine = ReportEngine()
        vulns = [make_vulnerability()]
        reports = engine.generate_all_reports("example.com", vulns, [], {})
        assert isinstance(reports, list)
        assert len(reports) > 0

    def test_report_contains_domain(self, make_vulnerability):
        from bbhunter.engines.reporting.engine import ReportEngine
        engine = ReportEngine()
        vulns = [make_vulnerability()]
        reports = engine.generate_all_reports("example.com", vulns, [], {})
        # At least one report should mention the domain
        all_content = str(reports)
        assert "example.com" in all_content

    def test_empty_vulns_produces_report(self):
        from bbhunter.engines.reporting.engine import ReportEngine
        engine = ReportEngine()
        reports = engine.generate_all_reports("example.com", [], [], {})
        assert isinstance(reports, list)

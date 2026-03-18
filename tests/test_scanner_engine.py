"""Tests for bbhunter.engines.scanner.engine (VulnerabilityScanner)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bbhunter.models import Endpoint, ScanStatus


class TestVulnerabilityScanner:
    """Test the scanner orchestrator."""

    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

    def test_scanner_initialises(self):
        from bbhunter.engines.scanner.engine import VulnerabilityScanner
        vs = VulnerabilityScanner()
        assert "xss" in vs.scanners
        assert "sqli" in vs.scanners
        assert len(vs.scanners) == 10

    @pytest.mark.asyncio
    async def test_run_returns_scan_result(self):
        from bbhunter.engines.scanner.engine import VulnerabilityScanner
        vs = VulnerabilityScanner()
        # Mock all individual scanners to return empty
        for scanner in vs.scanners.values():
            scanner.scan = AsyncMock(return_value=[])

        result = await vs.run("example.com", [], scanners=["xss"])
        assert result.status == ScanStatus.COMPLETED
        assert result.vulnerabilities_found == 0

    @pytest.mark.asyncio
    async def test_unknown_scanner_skipped(self):
        from bbhunter.engines.scanner.engine import VulnerabilityScanner
        vs = VulnerabilityScanner()
        for scanner in vs.scanners.values():
            scanner.scan = AsyncMock(return_value=[])

        result = await vs.run("example.com", [], scanners=["nonexistent_scanner"])
        assert result.status == ScanStatus.COMPLETED

    def test_set_payload_engine(self):
        from bbhunter.engines.scanner.engine import VulnerabilityScanner
        vs = VulnerabilityScanner()
        mock_pe = MagicMock()
        vs.set_payload_engine(mock_pe)
        assert vs._payload_engine is mock_pe

    def test_set_learning_engine(self):
        from bbhunter.engines.scanner.engine import VulnerabilityScanner
        vs = VulnerabilityScanner()
        mock_le = MagicMock()
        vs.set_learning_engine(mock_le)
        assert vs._learning_engine is mock_le

    @pytest.mark.asyncio
    async def test_scanner_error_recorded(self):
        from bbhunter.engines.scanner.engine import VulnerabilityScanner
        vs = VulnerabilityScanner()
        # Make the XSS scanner raise
        vs.scanners["xss"].scan = AsyncMock(side_effect=RuntimeError("boom"))
        for k, scanner in vs.scanners.items():
            if k != "xss":
                scanner.scan = AsyncMock(return_value=[])

        result = await vs.run("example.com", [], scanners=["xss"])
        assert len(result.errors) > 0
        assert "boom" in result.errors[0]

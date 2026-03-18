"""Tests for bbhunter.engines.payloads.engine (PayloadEngine)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


class TestPayloadEngine:
    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        mod._config = load_config(config_file)

    def test_generate_xss(self):
        from bbhunter.engines.payloads.engine import PayloadEngine
        pe = PayloadEngine()
        payloads = pe.generate(category="xss", context="html")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_generate_sqli(self):
        from bbhunter.engines.payloads.engine import PayloadEngine
        pe = PayloadEngine()
        payloads = pe.generate(category="sqli")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_generate_ssrf(self):
        from bbhunter.engines.payloads.engine import PayloadEngine
        pe = PayloadEngine()
        payloads = pe.generate(category="ssrf")
        assert isinstance(payloads, list)

    def test_generate_unknown_category(self):
        from bbhunter.engines.payloads.engine import PayloadEngine
        pe = PayloadEngine()
        payloads = pe.generate(category="nonexistent")
        assert isinstance(payloads, list)

    def test_waf_fingerprint_method_exists(self):
        from bbhunter.engines.payloads.engine import PayloadEngine
        pe = PayloadEngine()
        assert hasattr(pe, "fingerprint_waf")

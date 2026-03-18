"""Tests for bbhunter.engines.dashboard.api (FastAPI endpoints)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest


class TestDashboardAPI:
    @pytest.fixture(autouse=True)
    def _setup_config(self, config_file: Path):
        from bbhunter.config import load_config
        import bbhunter.config as mod
        cfg = load_config(config_file)
        cfg.dashboard.enable_auth = False  # disable auth for tests
        mod._config = cfg

    @pytest.fixture
    def client(self):
        """Create a TestClient for the dashboard app."""
        from fastapi.testclient import TestClient
        # Re-import to pick up the patched config
        from bbhunter.engines.dashboard import api as api_mod
        return TestClient(api_mod.app)

    def test_health_endpoint(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "timestamp" in data

    def test_dashboard_html(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "BBHunter" in resp.text

    def test_list_scans_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200

    def test_get_scan_not_found(self, client):
        resp = client.get("/api/scans/nonexistent-id")
        assert resp.status_code == 404

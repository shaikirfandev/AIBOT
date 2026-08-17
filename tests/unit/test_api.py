"""Tests for the FastAPI endpoints."""
import pytest
from httpx import ASGITransport, AsyncClient

import sys
from pathlib import Path

# Add packages to path
_root = Path(__file__).resolve().parent.parent.parent
for pkg_dir in (_root / "packages").iterdir():
    if pkg_dir.is_dir():
        sys.path.insert(0, str(pkg_dir))

sys.path.insert(0, str(_root / "apps" / "api"))

from app.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestProgramsAPI:
    @pytest.mark.asyncio
    async def test_create_org_and_program(self, client):
        # Create org
        resp = await client.post("/api/v1/organizations", json={"name": "Test Org", "slug": "test-org"})
        assert resp.status_code == 200
        org = resp.json()

        # Create program
        resp = await client.post("/api/v1/programs", json={
            "name": "Test Program",
            "organization_id": org["id"],
            "scope": {"domains": ["example.com"], "protocols": ["https"]},
        })
        assert resp.status_code == 200
        program = resp.json()
        assert program["name"] == "Test Program"

    @pytest.mark.asyncio
    async def test_list_programs(self, client):
        resp = await client.get("/api/v1/programs")
        assert resp.status_code == 200


class TestScansAPI:
    @pytest.mark.asyncio
    async def test_create_scan_no_program(self, client):
        resp = await client.post("/api/v1/scans", json={
            "program_id": "nonexistent",
            "target": "https://example.com",
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_scans(self, client):
        resp = await client.get("/api/v1/scans")
        assert resp.status_code == 200


class TestAgentsAPI:
    @pytest.mark.asyncio
    async def test_list_agent_types(self, client):
        resp = await client.get("/api/v1/agents/types")
        assert resp.status_code == 200
        types = resp.json()
        assert "recon" in types
        assert "crawler" in types

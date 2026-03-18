"""Tests for bbhunter.database module."""

from __future__ import annotations

import pytest


class TestDatabase:
    @pytest.mark.asyncio
    async def test_init_db_creates_tables(self):
        from bbhunter.database import init_db, get_session, Base
        await init_db("sqlite+aiosqlite:///:memory:")
        session = await get_session()
        assert session is not None
        await session.close()

    @pytest.mark.asyncio
    async def test_get_session_auto_init(self):
        """get_session should auto-init if not done yet."""
        import bbhunter.database as db_mod
        db_mod._async_engine = None
        db_mod._async_session_factory = None
        # This should trigger init_db internally
        session = await db_mod.get_session()
        assert session is not None
        await session.close()

    def test_sync_db_init(self):
        from bbhunter.database import init_sync_db
        SessionLocal = init_sync_db("sqlite:///:memory:")
        session = SessionLocal()
        assert session is not None
        session.close()

    def test_orm_models_defined(self):
        from bbhunter.database import (
            TargetRow, AssetRow, EndpointRow,
            VulnerabilityRow, ScanRow, FeedbackRow,
            ExploitChainRow,
        )
        assert TargetRow.__tablename__ == "targets"
        assert VulnerabilityRow.__tablename__ == "vulnerabilities"
        assert FeedbackRow.__tablename__ == "feedback"

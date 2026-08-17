"""In-memory store (replace with PostgreSQL/SQLAlchemy in production)."""
from __future__ import annotations

from typing import Any

# Simple in-memory stores for Phase 1
_stores: dict[str, dict[str, Any]] = {
    "organizations": {},
    "programs": {},
    "scans": {},
    "assets": {},
    "endpoints": {},
    "findings": {},
    "evidence": {},
    "events": {},
    "agent_jobs": {},
    "regression_tests": {},
    "regression_runs": {},
    "reports": {},
    "audit_logs": {},
}


async def init_db() -> None:
    """Initialize database (no-op for in-memory)."""
    pass


def get_store(name: str) -> dict[str, Any]:
    return _stores[name]

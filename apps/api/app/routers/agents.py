"""Agents API."""
from __future__ import annotations

from fastapi import APIRouter

from bbp_common import AGENT_REGISTRY

from app.services.database import get_store

router = APIRouter(tags=["agents"])


@router.get("/agents/types")
async def list_agent_types():
    return list(AGENT_REGISTRY.keys())


@router.get("/agents/jobs")
async def list_agent_jobs():
    return list(get_store("agent_jobs").values())

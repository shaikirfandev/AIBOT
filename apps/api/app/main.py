"""Bug Bounty Platform – FastAPI backend."""
from __future__ import annotations

import sys
from pathlib import Path

# Allow importing local packages without install
_root = Path(__file__).resolve().parent.parent.parent.parent
for pkg_dir in (_root / "packages").iterdir():
    if pkg_dir.is_dir():
        sys.path.insert(0, str(pkg_dir))

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import agents, findings, programs, reports, scans


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    # Startup
    from app.services.database import init_db
    await init_db()
    yield
    # Shutdown


app = FastAPI(
    title="Bug Bounty Platform API",
    version="0.1.0",
    description="Production-ready autonomous Bug Bounty Security Research Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(programs.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(agents.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")


@app.get("/health")
async def health():
    return {"status": "ok"}

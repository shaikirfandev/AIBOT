"""
Database layer using SQLAlchemy async with SQLite.
Provides persistence for all scan data, assets, and vulnerabilities.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from bbhunter.config import get_config


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# ORM Models
# ---------------------------------------------------------------------------

class TargetRow(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True)
    domain = Column(String, nullable=False, index=True)
    program = Column(String, default="")
    platform = Column(String, default="")
    scope_json = Column(Text, default="{}")
    authorization_json = Column(Text, default="{}")
    rules_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AssetRow(Base):
    __tablename__ = "assets"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, default="")
    asset_type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    source = Column(String, default="")
    in_scope = Column(Boolean, default=True)
    metadata_json = Column(Text, default="{}")
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class EndpointRow(Base):
    __tablename__ = "endpoints"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, default="")
    url = Column(String, nullable=False)
    method = Column(String, default="GET")
    status_code = Column(Integer, default=0)
    content_type = Column(String, default="")
    source = Column(String, default="")
    is_interesting = Column(Boolean, default=False)
    category = Column(String, default="")
    parameters_json = Column(Text, default="[]")
    headers_json = Column(Text, default="{}")
    auth_required = Column(Boolean, default=False)
    technology_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")


class VulnerabilityRow(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, default="")
    category = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    url = Column(String, default="")
    parameter = Column(String, default="")
    payload = Column(Text, default="")
    evidence = Column(Text, default="")
    request = Column(Text, default="")
    response = Column(Text, default="")
    steps_json = Column(Text, default="[]")
    impact = Column(Text, default="")
    remediation = Column(Text, default="")
    next_steps = Column(Text, default="")
    cvss_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    is_verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    source = Column(String, default="engine")
    chain_ids_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ScanRow(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_type = Column(String, nullable=False)
    status = Column(String, default="pending")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    assets_found = Column(Integer, default=0)
    endpoints_found = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    errors_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")


class ExploitChainRow(Base):
    __tablename__ = "exploit_chains"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    vulnerability_ids_json = Column(Text, default="[]")
    combined_severity = Column(String, default="high")
    impact = Column(Text, default="")
    attack_path_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")


class FeedbackRow(Base):
    __tablename__ = "feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(String, index=True)
    is_true_positive = Column(Boolean)
    researcher_notes = Column(Text, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Tables used by the scripts/ pipeline (shared schema)
# ---------------------------------------------------------------------------

class ParameterRow(Base):
    __tablename__ = "parameters"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    endpoint_id = Column(String, default="")
    name = Column(String, nullable=False)
    location = Column(String, default="query")
    sample_urls = Column(Text, default="[]")
    is_interesting = Column(Boolean, default=False)
    metadata_json = Column(Text, default="{}")
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class DnsRecordRow(Base):
    __tablename__ = "dns_records"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, default="")
    subdomain = Column(String, nullable=False)
    record_type = Column(String, default="")
    value = Column(String, default="")
    raw_line = Column(String, default="")
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class TechnologyRow(Base):
    __tablename__ = "technologies"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, default="")
    url = Column(String, nullable=False)
    header_name = Column(String, default="")
    header_value = Column(String, default="")
    tech_name = Column(String, default="")
    raw_headers = Column(Text, default="")
    discovered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class LlmChunkRow(Base):
    __tablename__ = "llm_chunks"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, default="")
    source_file = Column(String, nullable=False)
    chunk_index = Column(Integer, nullable=False)
    total_chunks = Column(Integer, default=0)
    chunk_hash = Column(String, default="")
    chunk_chars = Column(Integer, default=0)
    chunk_lines = Column(Integer, default=0)
    prompt_text = Column(Text, default="")
    response_text = Column(Text, default="")
    tokens_prompt = Column(Integer, default=0)
    tokens_eval = Column(Integer, default=0)
    duration_s = Column(Float, default=0.0)
    success = Column(Boolean, default=False)
    error = Column(Text, default="")
    llm_model = Column(String, default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class LlmAnalysisRow(Base):
    __tablename__ = "llm_analyses"

    id = Column(String, primary_key=True)
    target_id = Column(String, index=True, nullable=False)
    scan_id = Column(String, default="")
    source_file = Column(String, nullable=False)
    merged_text = Column(Text, default="")
    chunks_total = Column(Integer, default=0)
    chunks_done = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    total_duration_s = Column(Float, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ActionLogRow(Base):
    __tablename__ = "action_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    action = Column(String, nullable=False)
    target = Column(String, default="")
    step_name = Column(String, default="")
    tool_name = Column(String, default="")
    details_json = Column(Text, default="{}")
    level = Column(String, default="INFO")
    scan_id = Column(String, default="")


# ---------------------------------------------------------------------------
# Engine & Session
# ---------------------------------------------------------------------------

_async_engine = None
_async_session_factory = None


async def init_db(db_url: Optional[str] = None):
    """Initialize the async database engine and create tables."""
    global _async_engine, _async_session_factory

    if db_url is None:
        cfg = get_config()
        db_url = cfg.database.url

    _async_engine = create_async_engine(db_url, echo=False)
    _async_session_factory = async_sessionmaker(_async_engine, class_=AsyncSession, expire_on_commit=False)

    async with _async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:
    """Get an async database session."""
    if _async_session_factory is None:
        await init_db()
    return _async_session_factory()


def init_sync_db(db_url: str = "sqlite:///./data/bbhunter.db"):
    """Initialize a synchronous database (for CLI/scripts)."""
    engine = create_engine(db_url, echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)

"""SQLAlchemy ORM models for PostgreSQL."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.now(timezone.utc)


class Organization(Base):
    __tablename__ = "organizations"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    programs = relationship("Program", back_populates="organization")


class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255))
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"))
    role = Column(String(50), default="viewer")
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Program(Base):
    __tablename__ = "programs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text, default="")
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    scope = Column(JSON, default=dict)
    policy = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    organization = relationship("Organization", back_populates="programs")
    scans = relationship("Scan", back_populates="program")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("programs.id"), nullable=False)
    asset_type = Column(String(50), nullable=False)
    value = Column(String(2048), nullable=False)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    url = Column(String(4096), nullable=False)
    method = Column(String(10), default="GET")
    parameters = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    program_id = Column(UUID(as_uuid=True), ForeignKey("programs.id"), nullable=False)
    target = Column(String(2048), nullable=False)
    scan_type = Column(String(50), default="full")
    status = Column(String(20), default="pending")
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    findings_count = Column(Integer, default=0)
    assets_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    program = relationship("Program", back_populates="scans")


class AgentJob(Base):
    __tablename__ = "agent_jobs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    agent_type = Column(String(100), nullable=False)
    status = Column(String(20), default="idle")
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    result = Column(JSON, default=dict)
    error = Column(Text)


class DBEvent(Base):
    __tablename__ = "events"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    event_type = Column(String(100), nullable=False)
    data = Column(JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"))
    endpoint_id = Column(UUID(as_uuid=True), ForeignKey("endpoints.id"))
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    vuln_category = Column(String(50), default="other")
    severity = Column(String(20), default="informational")
    confidence = Column(Float, default=0.0)
    exploitability = Column(Float, default=0.0)
    evidence_quality = Column(Float, default=0.0)
    business_impact = Column(Text, default="")
    reproducibility = Column(Float, default=0.0)
    duplicate_probability = Column(Float, default=0.0)
    cwe = Column(String(20))
    cvss = Column(Float)
    owasp = Column(JSON, default=list)
    evidence = Column(JSON, default=dict)
    status = Column(String(30), default="candidate")
    fingerprint = Column(String(64))
    regression_status = Column(String(30))
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    evidence_type = Column(String(50), nullable=False)
    content = Column(JSON, default=dict)
    artifact_url = Column(String(2048))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class RegressionTest(Base):
    __tablename__ = "regression_tests"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False)
    test_type = Column(String(50), default="http")
    baseline_evidence = Column(JSON, default=dict)
    expected_behavior = Column(Text, default="")
    last_verified = Column(DateTime(timezone=True))
    status = Column(String(30), default="still_open")
    created_at = Column(DateTime(timezone=True), default=utcnow)


class RegressionRun(Base):
    __tablename__ = "regression_runs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    regression_test_id = Column(UUID(as_uuid=True), ForeignKey("regression_tests.id"), nullable=False)
    observed_behavior = Column(Text, default="")
    status = Column(String(30), default="still_open")
    run_at = Column(DateTime(timezone=True), default=utcnow)


class LLMRequestRecord(Base):
    __tablename__ = "llm_requests"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    model = Column(String(100))
    provider = Column(String(50))
    prompt = Column(Text)
    context = Column(JSON, default=dict)
    tokens_used = Column(Integer, default=0)
    cost = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class LLMResponseRecord(Base):
    __tablename__ = "llm_responses"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    request_id = Column(UUID(as_uuid=True), ForeignKey("llm_requests.id"), nullable=False)
    content = Column(Text, default="")
    structured = Column(JSON, default=dict)
    model = Column(String(100))
    tokens_used = Column(Integer, default=0)
    latency_ms = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Report(Base):
    __tablename__ = "reports"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    format = Column(String(20), default="pdf")
    content = Column(Text, default="")
    artifact_url = Column(String(2048))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    channel = Column(String(20), nullable=False)
    subject = Column(String(500), default="")
    body = Column(Text, default="")
    metadata_ = Column("metadata", JSON, default=dict)
    sent_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255), nullable=False)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime(timezone=True), default=utcnow)

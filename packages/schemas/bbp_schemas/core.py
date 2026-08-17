"""Core domain schemas used across all services."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, Enum):
    CANDIDATE = "candidate"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REPORTED = "reported"
    ACKNOWLEDGED = "acknowledged"
    FIXED = "fixed"
    REGRESSED = "regressed"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"
    UNVERIFIED = "unverified"


class RegressionStatus(str, Enum):
    FIXED = "fixed"
    STILL_OPEN = "still_open"
    REGRESSED = "regressed"
    REOPENED = "reopened"
    BEHAVIOR_CHANGED = "behavior_changed"
    ENDPOINT_REMOVED = "endpoint_removed"


class VulnCategory(str, Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    IDOR = "idor"
    CSRF = "csrf"
    SSTI = "ssti"
    COMMAND_INJECTION = "command_injection"
    OPEN_REDIRECT = "open_redirect"
    CORS = "cors"
    AUTH_BYPASS = "auth_bypass"
    RATE_LIMIT = "rate_limit"
    JWT = "jwt"
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"
    BUSINESS_LOGIC = "business_logic"
    ACCESS_CONTROL = "access_control"
    XXE = "xxe"
    INFORMATION_DISCLOSURE = "information_disclosure"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    OTHER = "other"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class EventType(str, Enum):
    SCAN_REQUESTED = "scan.requested"
    SCAN_STARTED = "scan.started"
    SCOPE_VALIDATED = "scope.validated"
    ASSET_DISCOVERED = "asset.discovered"
    ENDPOINT_DISCOVERED = "endpoint.discovered"
    TEST_REQUESTED = "test.requested"
    TEST_COMPLETED = "test.completed"
    FINDING_CANDIDATE = "finding.candidate"
    FINDING_VALIDATED = "finding.validated"
    FINDING_DEDUPLICATED = "finding.deduplicated"
    LLM_ANALYSIS_REQUESTED = "llm.analysis.requested"
    LLM_ANALYSIS_COMPLETED = "llm.analysis.completed"
    REGRESSION_REQUESTED = "regression.requested"
    REGRESSION_COMPLETED = "regression.completed"
    REPORT_GENERATED = "report.generated"
    AGENT_FAILED = "agent.failed"
    SCAN_COMPLETED = "scan.completed"


# ---------------------------------------------------------------------------
# Base & ID helpers
# ---------------------------------------------------------------------------

def new_id() -> str:
    return str(uuid.uuid4())


class TimestampMixin(BaseModel):
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Scope schemas
# ---------------------------------------------------------------------------

class ScopeRule(BaseModel):
    """A single scope entry."""
    domains: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    ip_ranges: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=lambda: ["https"])
    excluded_paths: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)


class ScopePolicy(BaseModel):
    """Rate limits and concurrency constraints."""
    max_requests_per_second: int = 10
    max_concurrent_requests: int = 5
    max_total_requests: int = 100_000
    prohibited_actions: list[str] = Field(
        default_factory=lambda: [
            "denial_of_service", "destructive_testing", "credential_theft",
            "lateral_movement", "persistence", "stealth_evasion",
        ]
    )


# ---------------------------------------------------------------------------
# Program / Organization
# ---------------------------------------------------------------------------

class OrganizationCreate(BaseModel):
    name: str
    slug: str


class Organization(OrganizationCreate, TimestampMixin):
    id: str = Field(default_factory=new_id)


class ProgramCreate(BaseModel):
    name: str
    organization_id: str
    description: str = ""
    scope: ScopeRule = Field(default_factory=ScopeRule)
    policy: ScopePolicy = Field(default_factory=ScopePolicy)


class Program(ProgramCreate, TimestampMixin):
    id: str = Field(default_factory=new_id)


# ---------------------------------------------------------------------------
# Asset / Endpoint
# ---------------------------------------------------------------------------

class AssetCreate(BaseModel):
    program_id: str
    asset_type: str  # domain, subdomain, ip, url, api
    value: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class Asset(AssetCreate, TimestampMixin):
    id: str = Field(default_factory=new_id)


class EndpointCreate(BaseModel):
    asset_id: str
    url: str
    method: str = "GET"
    parameters: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Endpoint(EndpointCreate, TimestampMixin):
    id: str = Field(default_factory=new_id)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    program_id: str
    target: str
    scan_type: str = "full"


class Scan(ScanCreate, TimestampMixin):
    id: str = Field(default_factory=new_id)
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    assets_count: int = 0


# ---------------------------------------------------------------------------
# Agent / Job
# ---------------------------------------------------------------------------

class AgentConfig(BaseModel):
    agent_id: str = Field(default_factory=new_id)
    agent_type: str
    objective: str = ""
    permissions: list[str] = Field(default_factory=list)
    rate_limit: int = 10
    timeout: int = 300
    retry_policy: dict[str, Any] = Field(default_factory=lambda: {"max_retries": 3, "backoff": "exponential"})


class AgentJob(BaseModel):
    id: str = Field(default_factory=new_id)
    scan_id: str
    agent_type: str
    status: AgentStatus = AgentStatus.IDLE
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class FindingCreate(BaseModel):
    scan_id: str
    asset_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    title: str
    description: str = ""
    vuln_category: VulnCategory = VulnCategory.OTHER
    severity: Severity = Severity.INFORMATIONAL
    confidence: float = 0.0
    exploitability: float = 0.0
    evidence_quality: float = 0.0
    business_impact: str = ""
    reproducibility: float = 0.0
    duplicate_probability: float = 0.0
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    owasp: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)


class Finding(FindingCreate, TimestampMixin):
    id: str = Field(default_factory=new_id)
    status: FindingStatus = FindingStatus.CANDIDATE
    fingerprint: Optional[str] = None
    regression_status: Optional[RegressionStatus] = None


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class Evidence(BaseModel):
    id: str = Field(default_factory=new_id)
    finding_id: str
    evidence_type: str  # request, response, screenshot, trace, scanner, llm
    content: dict[str, Any] = Field(default_factory=dict)
    artifact_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Regression
# ---------------------------------------------------------------------------

class RegressionTest(BaseModel):
    id: str = Field(default_factory=new_id)
    finding_id: str
    test_type: str = "http"
    baseline_evidence: dict[str, Any] = Field(default_factory=dict)
    expected_behavior: str = ""
    last_verified: Optional[datetime] = None
    status: RegressionStatus = RegressionStatus.STILL_OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RegressionRun(BaseModel):
    id: str = Field(default_factory=new_id)
    regression_test_id: str
    observed_behavior: str = ""
    status: RegressionStatus = RegressionStatus.STILL_OPEN
    run_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------

class LLMRequest(BaseModel):
    id: str = Field(default_factory=new_id)
    model: str = "gpt-4o-mini"
    provider: str = "openai"
    prompt: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    tokens_used: int = 0
    cost: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LLMResponse(BaseModel):
    id: str = Field(default_factory=new_id)
    request_id: str
    content: str = ""
    structured: dict[str, Any] = Field(default_factory=dict)
    model: str = ""
    tokens_used: int = 0
    latency_ms: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class Event(BaseModel):
    id: str = Field(default_factory=new_id)
    scan_id: str
    event_type: EventType
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class Report(BaseModel):
    id: str = Field(default_factory=new_id)
    scan_id: str
    format: str = "pdf"
    content: str = ""
    artifact_url: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Notification
# ---------------------------------------------------------------------------

class Notification(BaseModel):
    id: str = Field(default_factory=new_id)
    channel: str  # web, email, slack, teams, webhook
    subject: str = ""
    body: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    sent_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

class AuditLog(BaseModel):
    id: str = Field(default_factory=new_id)
    user_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

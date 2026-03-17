"""
Core data models used across all engines.
"""

from __future__ import annotations

import uuid
from datetime import datetime
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
    RACE_CONDITION = "race_condition"
    GRAPHQL_ABUSE = "graphql_abuse"
    API_PRIVESC = "api_privesc"
    CLOUD_MISCONFIG = "cloud_misconfig"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OTHER = "other"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    URL = "url"
    API_ENDPOINT = "api_endpoint"
    CLOUD_ASSET = "cloud_asset"
    REPOSITORY = "repository"
    EMAIL = "email"
    S3_BUCKET = "s3_bucket"


# ---------------------------------------------------------------------------
# Target & Authorization
# ---------------------------------------------------------------------------

class ScopeRule(BaseModel):
    include: list[str] = Field(default_factory=list)
    exclude: list[str] = Field(default_factory=list)


class Authorization(BaseModel):
    type: str = "bug_bounty_program"
    platform: str = ""
    program_url: str = ""
    authorized_date: str = ""
    expiry_date: str = ""
    tester: str = ""


class Target(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    domain: str
    scope: ScopeRule = ScopeRule()
    authorization: Authorization = Authorization()
    rules: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    asset_type: AssetType
    value: str                    # domain name, IP, URL, etc.
    source: str = ""              # how it was discovered
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Surface Mapping
# ---------------------------------------------------------------------------

class Endpoint(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    url: str
    method: str = "GET"
    parameters: list[Parameter] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    auth_required: bool = False
    technology: list[str] = Field(default_factory=list)
    content_type: str = ""
    status_code: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class Parameter(BaseModel):
    name: str
    location: str = "query"       # query, body, header, cookie, path
    param_type: str = "string"
    required: bool = False
    sample_value: str = ""


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    scan_id: str = ""
    category: VulnCategory
    severity: Severity
    title: str
    description: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    steps_to_reproduce: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    confidence: float = 0.0       # 0.0 to 1.0
    is_verified: bool = False
    false_positive: bool = False
    chain_ids: list[str] = Field(default_factory=list)  # linked vulns
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    scan_type: str                # recon, surface_map, vuln_scan, full
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    assets_found: int = 0
    endpoints_found: int = 0
    vulnerabilities_found: int = 0
    errors: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Exploit Chain
# ---------------------------------------------------------------------------

class ExploitChain(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    title: str
    description: str = ""
    vulnerability_ids: list[str] = Field(default_factory=list)
    combined_severity: Severity = Severity.HIGH
    impact: str = ""
    attack_path: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class Report(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str
    title: str
    vulnerability: Vulnerability
    chain: Optional[ExploitChain] = None
    format: str = "markdown"
    content: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)


# We need to rebuild Endpoint since Parameter was defined after it was referenced
Endpoint.model_rebuild()

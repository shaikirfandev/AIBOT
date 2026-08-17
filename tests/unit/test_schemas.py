"""Tests for the core schemas."""
import pytest
from bbp_schemas.core import (
    Finding,
    FindingCreate,
    FindingStatus,
    Organization,
    Program,
    ProgramCreate,
    Scan,
    ScanCreate,
    ScanStatus,
    ScopePolicy,
    ScopeRule,
    Severity,
    VulnCategory,
    new_id,
)


class TestSchemas:
    def test_new_id(self):
        id1 = new_id()
        id2 = new_id()
        assert id1 != id2
        assert len(id1) == 36  # UUID format

    def test_scope_rule_defaults(self):
        rule = ScopeRule()
        assert rule.protocols == ["https"]
        assert rule.domains == []

    def test_scope_policy_defaults(self):
        policy = ScopePolicy()
        assert policy.max_requests_per_second == 10
        assert "denial_of_service" in policy.prohibited_actions

    def test_program_create(self):
        p = ProgramCreate(
            name="Test Program",
            organization_id="org-1",
            scope=ScopeRule(domains=["example.com"]),
        )
        assert p.name == "Test Program"

    def test_finding_create(self):
        f = FindingCreate(
            scan_id="scan-1",
            title="XSS in search",
            vuln_category=VulnCategory.XSS,
            severity=Severity.HIGH,
            confidence=0.85,
        )
        assert f.severity == Severity.HIGH

    def test_finding_has_defaults(self):
        f = Finding(scan_id="s1", title="Test")
        assert f.status == FindingStatus.CANDIDATE
        assert f.id is not None

    def test_scan_defaults(self):
        s = Scan(program_id="p1", target="https://example.com")
        assert s.status == ScanStatus.PENDING

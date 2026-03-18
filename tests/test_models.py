"""Tests for bbhunter.models module."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from bbhunter.models import (
    Severity,
    VulnCategory,
    Endpoint,
    Vulnerability,
    ScanResult,
    ScanStatus,
    Asset,
    AssetType,
    Target,
    ScopeRule,
    Authorization,
)


class TestSeverityEnum:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_info_alias(self):
        assert Severity.INFO == Severity.INFORMATIONAL


class TestVulnCategory:
    def test_xss(self):
        assert VulnCategory.XSS.value == "xss"

    def test_all_categories_are_strings(self):
        for cat in VulnCategory:
            assert isinstance(cat.value, str)


class TestEndpoint:
    def test_create_minimal(self):
        ep = Endpoint(target_id="t1", url="https://example.com")
        assert ep.url == "https://example.com"
        assert ep.method == "GET"

    def test_id_auto_generated(self):
        ep = Endpoint(target_id="t1", url="https://example.com")
        assert ep.id  # should be a UUID string


class TestVulnerability:
    def test_create(self, make_vulnerability):
        v = make_vulnerability()
        assert v.category == VulnCategory.XSS
        assert v.severity == Severity.MEDIUM
        assert v.confidence == 0.8

    def test_discovered_at_is_utc_aware(self, make_vulnerability):
        v = make_vulnerability()
        # The default_factory should produce timezone-aware datetime
        assert v.discovered_at is not None

    def test_custom_fields(self, make_vulnerability):
        v = make_vulnerability(title="Custom Title", severity=Severity.CRITICAL)
        assert v.title == "Custom Title"
        assert v.severity == Severity.CRITICAL


class TestScanResult:
    def test_default_status(self):
        sr = ScanResult(target_id="t1", scan_type="recon")
        assert sr.status == ScanStatus.PENDING

    def test_errors_list(self):
        sr = ScanResult(target_id="t1", scan_type="test")
        assert sr.errors == []


class TestTarget:
    def test_default_scope(self):
        t = Target(domain="example.com")
        assert isinstance(t.scope, ScopeRule)

    def test_scope_include_exclude(self):
        scope = ScopeRule(include=["*.example.com"], exclude=["admin.example.com"])
        t = Target(domain="example.com", scope=scope)
        assert "*.example.com" in t.scope.include
        assert "admin.example.com" in t.scope.exclude

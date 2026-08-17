"""Tests for the scope engine."""
import pytest
from bbp_schemas.core import ScopePolicy, ScopeRule
from bbp_scope import ScopeEngine, ScopeViolation, RateLimitExceeded, create_finding_fingerprint


def _engine(domains=None, excluded_domains=None, excluded_paths=None):
    scope = ScopeRule(
        domains=domains or ["example.com"],
        excluded_domains=excluded_domains or [],
        excluded_paths=excluded_paths or [],
        protocols=["https", "http"],
    )
    policy = ScopePolicy(max_requests_per_second=100, max_total_requests=1000)
    return ScopeEngine(scope, policy)


class TestScopeEngine:
    def test_allowed_domain(self):
        engine = _engine(domains=["example.com"])
        engine.check_target("https://example.com/api/v1")

    def test_subdomain_allowed(self):
        engine = _engine(domains=["example.com"])
        engine.check_target("https://api.example.com/test")

    def test_disallowed_domain(self):
        engine = _engine(domains=["example.com"])
        with pytest.raises(ScopeViolation):
            engine.check_target("https://evil.com/test")

    def test_excluded_domain(self):
        engine = _engine(domains=["example.com"], excluded_domains=["admin.example.com"])
        with pytest.raises(ScopeViolation):
            engine.check_target("https://admin.example.com/test")

    def test_excluded_path(self):
        engine = _engine(domains=["example.com"], excluded_paths=["/admin/*"])
        with pytest.raises(ScopeViolation):
            engine.check_target("https://example.com/admin/settings")

    def test_prohibited_action(self):
        engine = _engine()
        with pytest.raises(ScopeViolation):
            engine.check_action("denial_of_service")

    def test_allowed_action(self):
        engine = _engine()
        engine.check_action("scan")

    def test_request_budget(self):
        scope = ScopeRule(domains=["example.com"], protocols=["https", "http"])
        policy = ScopePolicy(max_requests_per_second=10000, max_total_requests=2)
        engine = ScopeEngine(scope, policy)
        engine.check_target("https://example.com/1")
        engine.check_target("https://example.com/2")
        with pytest.raises(ScopeViolation, match="budget"):
            engine.check_target("https://example.com/3")

    def test_audit_log(self):
        engine = _engine()
        engine.check_target("https://example.com/test")
        assert len(engine.audit_log) == 1
        assert engine.audit_log[0]["allowed"] is True


class TestFindingFingerprint:
    def test_deterministic(self):
        fp1 = create_finding_fingerprint("example.com", "/api/users", "id", "idor")
        fp2 = create_finding_fingerprint("example.com", "/api/users", "id", "idor")
        assert fp1 == fp2

    def test_different_inputs(self):
        fp1 = create_finding_fingerprint("example.com", "/api/users", "id", "idor")
        fp2 = create_finding_fingerprint("example.com", "/api/posts", "id", "idor")
        assert fp1 != fp2

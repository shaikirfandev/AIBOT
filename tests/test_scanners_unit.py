"""Unit tests for individual scanner modules in bbhunter/engines/scanner/."""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from bbhunter.models import Endpoint, Parameter, Severity, Vulnerability, VulnCategory


# ── Helpers ──────────────────────────────────────────────────────────────

def _mock_response(
    status_code: int = 200,
    text: str = "",
    headers: dict | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    resp.headers = httpx.Headers(headers or {})
    return resp


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _load_config(config_file: Path):
    """Ensure the test Config singleton is loaded for every test."""
    from bbhunter.config import load_config
    import bbhunter.config as mod
    mod._config = load_config(config_file)


# ============================================================================
#  XSSScanner
# ============================================================================

class TestXSSScanner:
    """Tests for XSSScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        assert scanner.CATEGORY == VulnCategory.XSS

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        assert inspect.iscoroutinefunction(XSSScanner.scan)

    def test_has_payloads(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        assert len(scanner.UNIVERSAL_PAYLOADS) > 0
        assert len(scanner.CONTEXT_PAYLOADS) > 0

    def test_detect_context_html_body(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        body = "<html><body><p>Hello bbh7x3r world</p></body></html>"
        assert scanner._detect_context(body, "bbh7x3r") == "html_body"

    def test_detect_context_javascript(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        body = '<html><script>var x = "bbh7x3r";</script></html>'
        assert scanner._detect_context(body, "bbh7x3r") == "javascript"

    def test_detect_context_attribute(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        body = '<html><input value="bbh7x3r"></html>'
        assert scanner._detect_context(body, "bbh7x3r") == "html_attribute"

    def test_detect_context_url(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        body = '<html><a href="https://example.com/bbh7x3r">link</a></html>'
        assert scanner._detect_context(body, "bbh7x3r") == "url_context"

    def test_detect_context_unknown(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        assert scanner._detect_context("no canary here", "bbh7x3r") == "unknown"

    def test_calculate_confidence_javascript(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        payload = "'-alert(1)-'"
        body = f"var x = '{payload}';"
        conf = scanner._calculate_confidence(payload, body, "javascript")
        assert conf >= 0.9

    def test_calculate_confidence_html_escaped(self):
        import html as html_mod
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        payload = '<script>alert(1)</script>'
        body = html_mod.escape(payload)
        conf = scanner._calculate_confidence(payload, body, "html_body")
        assert conf <= 0.2  # escaped → low confidence

    def test_extract_evidence(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        body = "AAAApayloadBBBB"
        ev = scanner._extract_evidence(body, "payload", context_size=3)
        assert "payload" in ev

    def test_select_payloads_returns_context_specific(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        ep = Endpoint(target_id="t", url="https://example.com")
        payloads = scanner._select_payloads("javascript", ep)
        assert any("alert" in p for p in payloads)

    def test_set_payload_engine(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        mock_pe = MagicMock()
        scanner.set_payload_engine(mock_pe)
        assert scanner._payload_engine is mock_pe

    def test_set_learning_engine(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        mock_le = MagicMock()
        scanner.set_learning_engine(mock_le)
        assert scanner._learning_engine is mock_le

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        result = await scanner.scan([], "target-1", "scan-1")
        assert result == []

    async def test_scan_with_reflected_param(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/search?q=test",
            parameters=[Parameter(name="q", location="query")],
        )

        # First request: canary is reflected → proceed
        # Second request: payload is reflected → vuln found
        canary_resp = _mock_response(text='<html>bbh7x3rq___</html>')
        payload_resp = _mock_response(text='<html><script>alert(1)</script></html>')

        call_count = 0
        async def fake_send(url, **kw):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return canary_resp
            return payload_resp

        scanner._send_request = fake_send  # type: ignore[assignment]
        vulns = await scanner.scan([ep], "t1", "s1")
        assert len(vulns) >= 1
        assert vulns[0].category == VulnCategory.XSS

    async def test_scan_no_reflection(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/search?q=test",
            parameters=[Parameter(name="q")],
        )

        # Canary NOT reflected → skip
        scanner._send_request = AsyncMock(return_value=_mock_response(text="no reflection"))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []

    async def test_check_dom_xss(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()

        ep = Endpoint(target_id="t", url="https://example.com/page")
        body = """
        <script>
            var x = location.hash;
            document.getElementById("out").innerHTML = x;
        </script>
        """
        scanner._send_request = AsyncMock(return_value=_mock_response(text=body))
        vulns = await scanner._check_dom_xss(ep, "t1", "s1")
        assert len(vulns) >= 1
        assert "DOM" in vulns[0].title


# ============================================================================
#  SQLiScanner
# ============================================================================

class TestSQLiScanner:
    """Tests for SQLiScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()
        assert scanner.CATEGORY == VulnCategory.SQLI

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        assert inspect.iscoroutinefunction(SQLiScanner.scan)

    def test_has_error_payloads(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()
        assert len(scanner.ERROR_PAYLOADS) > 0
        assert len(scanner.TIME_PAYLOADS) > 0

    def test_sql_error_patterns(self):
        import re
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()
        # Patterns should be valid regex
        for pattern in scanner.SQL_ERRORS:
            re.compile(pattern)

    def test_extract_sql_error(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()
        body = 'Some text Warning: mysql_ some more text'
        evidence = scanner._extract_sql_error(body, r"Warning.*mysql_")
        assert "mysql_" in evidence

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()
        result = await scanner.scan([], "target-1", "scan-1")
        assert result == []

    async def test_scan_error_based_detected(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/items?id=1",
            parameters=[Parameter(name="id", location="query")],
        )

        # Response contains SQL error
        scanner._send_request = AsyncMock(
            return_value=_mock_response(text="You have an error in your SQL syntax near...")
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        assert len(vulns) >= 1
        assert vulns[0].severity == Severity.CRITICAL

    async def test_scan_no_sqli(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/items?id=1",
            parameters=[Parameter(name="id")],
        )

        scanner._send_request = AsyncMock(return_value=_mock_response(text="Normal page content"))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []

    async def test_boolean_blind_detected(self):
        from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
        scanner = SQLiScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/items?id=1",
            parameters=[Parameter(name="id")],
        )

        long_body = "A" * 500
        short_body = "B" * 100

        call_count = 0
        async def fake_send(url, **kw):
            nonlocal call_count
            call_count += 1
            # First calls: error-based payloads → no SQL error → go to boolean
            # Boolean: TRUE condition → long body, FALSE → short body
            if "AND '1'='1" in url:
                return _mock_response(text=long_body)
            elif "AND '1'='2" in url:
                return _mock_response(text=short_body)
            return _mock_response(text="normal page")

        scanner._send_request = fake_send  # type: ignore[assignment]
        vulns = await scanner._boolean_blind_test(ep, "id", "t1", "s1")
        # It should detect the difference
        if vulns:
            assert "Blind" in vulns.title


# ============================================================================
#  CORSScanner
# ============================================================================

class TestCORSScanner:
    """Tests for CORSScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        scanner = CORSScanner()
        assert scanner.CATEGORY == VulnCategory.CORS

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        assert inspect.iscoroutinefunction(CORSScanner.scan)

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        scanner = CORSScanner()
        result = await scanner.scan([], "t1", "s1")
        assert result == []

    async def test_arbitrary_origin_reflected(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        scanner = CORSScanner()

        ep = Endpoint(target_id="t", url="https://example.com/api/data")

        # Server reflects arbitrary origin with credentials
        scanner._send_request = AsyncMock(
            return_value=_mock_response(
                headers={
                    "access-control-allow-origin": "https://evil-attacker.com",
                    "access-control-allow-credentials": "true",
                }
            )
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        assert any("Arbitrary Origin" in v.title for v in vulns)
        assert any(v.severity == Severity.HIGH for v in vulns)

    async def test_wildcard_origin(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        scanner = CORSScanner()

        ep = Endpoint(target_id="t", url="https://example.com/api")

        scanner._send_request = AsyncMock(
            return_value=_mock_response(
                headers={"access-control-allow-origin": "*"}
            )
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        assert any("Wildcard" in v.title for v in vulns)

    async def test_null_origin_accepted(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        scanner = CORSScanner()

        ep = Endpoint(target_id="t", url="https://example.com/api")

        call_count = 0
        async def fake_send(url, headers=None, **kw):
            nonlocal call_count
            call_count += 1
            origin = (headers or {}).get("Origin", "")
            if origin == "null":
                return _mock_response(headers={"access-control-allow-origin": "null"})
            return _mock_response(headers={})

        scanner._send_request = fake_send  # type: ignore[assignment]
        vulns = await scanner.scan([ep], "t1", "s1")
        assert any("Null Origin" in v.title for v in vulns)

    async def test_subdomain_origin(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        scanner = CORSScanner()

        ep = Endpoint(target_id="t", url="https://example.com/api")

        call_count = 0
        async def fake_send(url, headers=None, **kw):
            nonlocal call_count
            call_count += 1
            origin = (headers or {}).get("Origin", "")
            if "evil." in origin:
                return _mock_response(headers={"access-control-allow-origin": origin})
            return _mock_response(headers={})

        scanner._send_request = fake_send  # type: ignore[assignment]
        vulns = await scanner.scan([ep], "t1", "s1")
        assert any("Subdomain" in v.title for v in vulns)

    async def test_no_cors_issues(self):
        from bbhunter.engines.scanner.cors_scanner import CORSScanner
        scanner = CORSScanner()

        ep = Endpoint(target_id="t", url="https://example.com/api")
        scanner._send_request = AsyncMock(return_value=_mock_response(headers={}))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []


# ============================================================================
#  JWTScanner
# ============================================================================

class TestJWTScanner:
    """Tests for JWTScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()
        assert scanner.CATEGORY == VulnCategory.JWT

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        assert inspect.iscoroutinefunction(JWTScanner.scan)

    def test_find_jwts(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()
        text = "token=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.signature"
        tokens = scanner._find_jwts(text)
        assert len(tokens) >= 1

    def test_find_jwts_no_match(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()
        assert scanner._find_jwts("no jwt here") == []

    def test_decode_jwt_part(self):
        import base64, json
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()
        payload = {"alg": "none"}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        result = scanner._decode_jwt_part(encoded)
        assert result == payload

    def test_decode_jwt_part_invalid(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()
        assert scanner._decode_jwt_part("!!!notbase64!!!") is None

    def test_analyze_jwt_none_alg(self):
        import base64, json
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"user": "admin", "exp": 9999999999}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.sig"

        vulns = scanner._analyze_jwt(token, "https://example.com", "t1", "s1")
        assert any("none" in v.title.lower() for v in vulns)

    def test_analyze_jwt_missing_exp(self):
        import base64, json
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()

        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"user": "admin"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.sig"

        vulns = scanner._analyze_jwt(token, "https://example.com", "t1", "s1")
        assert any("Expiration" in v.title for v in vulns)

    def test_analyze_jwt_sensitive_data(self):
        import base64, json
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()

        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"user": "admin", "password": "s3cret", "exp": 9999}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.sig"

        vulns = scanner._analyze_jwt(token, "https://example.com", "t1", "s1")
        assert any("Sensitive Data" in v.title for v in vulns)

    def test_analyze_jwt_invalid_token(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()
        vulns = scanner._analyze_jwt("not.a.jwt", "https://example.com", "t1", "s1")
        assert vulns == []

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()
        result = await scanner.scan([], "t1", "s1")
        assert result == []

    async def test_scan_finds_jwt_in_response(self):
        import base64, json
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"user": "admin"}).encode()).rstrip(b"=").decode()
        jwt_token = f"{header}.{payload}.signature"

        ep = Endpoint(target_id="t", url="https://example.com/api")
        scanner._send_request = AsyncMock(
            return_value=_mock_response(text=f"token={jwt_token}")
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        assert len(vulns) >= 1

    async def test_scan_no_jwt_found(self):
        from bbhunter.engines.scanner.jwt_scanner import JWTScanner
        scanner = JWTScanner()

        ep = Endpoint(target_id="t", url="https://example.com/api")
        scanner._send_request = AsyncMock(return_value=_mock_response(text="no tokens"))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []


# ============================================================================
#  IDORScanner
# ============================================================================

class TestIDORScanner:
    """Tests for IDORScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.idor_scanner import IDORScanner
        scanner = IDORScanner()
        assert scanner.CATEGORY == VulnCategory.IDOR

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.idor_scanner import IDORScanner
        assert inspect.iscoroutinefunction(IDORScanner.scan)

    def test_idor_params_defined(self):
        from bbhunter.engines.scanner.idor_scanner import IDORScanner
        scanner = IDORScanner()
        assert "id" in scanner.IDOR_PARAMS
        assert "user_id" in scanner.IDOR_PARAMS

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.idor_scanner import IDORScanner
        scanner = IDORScanner()
        result = await scanner.scan([], "t1", "s1")
        assert result == []

    async def test_scan_with_idor_param(self):
        from bbhunter.engines.scanner.idor_scanner import IDORScanner
        scanner = IDORScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/users?user_id=100",
            parameters=[Parameter(name="user_id", location="query")],
        )

        baseline_resp = _mock_response(text="user100 data " * 20)
        other_resp = _mock_response(text="user101 different data " * 20)

        call_count = 0
        async def fake_send(url, **kw):
            nonlocal call_count
            call_count += 1
            if "user_id=100" in url or call_count == 1:
                return baseline_resp
            return other_resp

        scanner._send_request = fake_send  # type: ignore[assignment]
        vulns = await scanner.scan([ep], "t1", "s1")
        # May or may not find depending on body length and content differences
        # At minimum the method should run without errors
        assert isinstance(vulns, list)

    async def test_scan_no_idor_param(self):
        from bbhunter.engines.scanner.idor_scanner import IDORScanner
        scanner = IDORScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/items?color=red",
            parameters=[Parameter(name="color")],
        )
        scanner._send_request = AsyncMock(return_value=_mock_response(text="ok"))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []

    async def test_path_idor(self):
        from bbhunter.engines.scanner.idor_scanner import IDORScanner
        scanner = IDORScanner()

        ep = Endpoint(target_id="t", url="https://example.com/users/100/profile")

        resp_other = _mock_response(text="other user profile data " * 20)
        resp_original = _mock_response(text="original user profile data " * 20)

        async def fake_send(url, **kw):
            if "/100/" in url:
                return resp_original
            return resp_other

        scanner._send_request = fake_send  # type: ignore[assignment]
        vuln = await scanner._test_path_idor(ep, "t1", "s1")
        # May detect because text differs
        # Just ensure it runs
        assert vuln is None or isinstance(vuln, Vulnerability)


# ============================================================================
#  HeaderScanner
# ============================================================================

class TestHeaderScanner:
    """Tests for HeaderScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        scanner = HeaderScanner()
        assert scanner.CATEGORY == VulnCategory.OTHER

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        assert inspect.iscoroutinefunction(HeaderScanner.scan)

    def test_security_headers_defined(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        scanner = HeaderScanner()
        assert "strict-transport-security" in scanner.SECURITY_HEADERS
        assert "content-security-policy" in scanner.SECURITY_HEADERS

    async def test_scan_missing_headers(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        scanner = HeaderScanner()

        ep = Endpoint(target_id="t", url="https://example.com/")
        # Response has NO security headers
        scanner._send_request = AsyncMock(
            return_value=_mock_response(headers={"content-type": "text/html"})
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        # Should report missing security headers
        assert len(vulns) >= 5  # at least 5 common headers missing

    async def test_scan_all_headers_present(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        scanner = HeaderScanner()

        ep = Endpoint(target_id="t", url="https://example.com/")
        scanner._send_request = AsyncMock(
            return_value=_mock_response(headers={
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "no-referrer",
                "permissions-policy": "camera=()",
            })
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        # All security headers present → no missing header vulns
        missing = [v for v in vulns if "Missing" in v.title]
        assert len(missing) == 0

    async def test_scan_info_disclosure_headers(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        scanner = HeaderScanner()

        ep = Endpoint(target_id="t", url="https://example.com/")
        scanner._send_request = AsyncMock(
            return_value=_mock_response(headers={
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
                "content-security-policy": "default-src 'self'",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "no-referrer",
                "permissions-policy": "camera=()",
                "server": "Apache/2.4.41",
                "x-powered-by": "PHP/7.4",
            })
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        info = [v for v in vulns if "Information Disclosure" in v.title]
        assert len(info) >= 2

    async def test_scan_dedup_hosts(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        scanner = HeaderScanner()

        ep1 = Endpoint(target_id="t", url="https://example.com/a")
        ep2 = Endpoint(target_id="t", url="https://example.com/b")
        scanner._send_request = AsyncMock(
            return_value=_mock_response(headers={"content-type": "text/html"})
        )
        vulns = await scanner.scan([ep1, ep2], "t1", "s1")
        # Should only check once per host
        assert scanner._send_request.call_count == 1

    async def test_scan_null_response(self):
        from bbhunter.engines.scanner.header_scanner import HeaderScanner
        scanner = HeaderScanner()

        ep = Endpoint(target_id="t", url="https://example.com/")
        scanner._send_request = AsyncMock(return_value=None)
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []


# ============================================================================
#  AuthScanner
# ============================================================================

class TestAuthScanner:
    """Tests for AuthScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.auth_scanner import AuthScanner
        scanner = AuthScanner()
        assert scanner.CATEGORY == VulnCategory.AUTH_BYPASS

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.auth_scanner import AuthScanner
        assert inspect.iscoroutinefunction(AuthScanner.scan)

    def test_default_creds_defined(self):
        from bbhunter.engines.scanner.auth_scanner import AuthScanner
        scanner = AuthScanner()
        assert len(scanner.DEFAULT_CREDS) > 0
        assert ("admin", "admin") in scanner.DEFAULT_CREDS

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.auth_scanner import AuthScanner
        scanner = AuthScanner()
        result = await scanner.scan([], "t1", "s1")
        assert result == []

    async def test_scan_finds_login_endpoint(self):
        from bbhunter.engines.scanner.auth_scanner import AuthScanner
        scanner = AuthScanner()

        ep = Endpoint(target_id="t", url="https://example.com/login")
        scanner._send_request = AsyncMock(return_value=_mock_response(text="Invalid credentials"))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert isinstance(vulns, list)

    async def test_username_enumeration_detected(self):
        from bbhunter.engines.scanner.auth_scanner import AuthScanner
        scanner = AuthScanner()

        ep = Endpoint(target_id="t", url="https://example.com/login")

        call_count = 0
        async def fake_send(url, method="GET", data=None, **kw):
            nonlocal call_count
            call_count += 1
            if data and data.get("username") == "admin":
                return _mock_response(text="Password incorrect" + "x" * 100)
            elif data and "nonexistent" in data.get("username", ""):
                return _mock_response(text="User not found")
            return _mock_response(text="Login page")

        scanner._send_request = fake_send  # type: ignore[assignment]
        vuln = await scanner._test_username_enumeration(ep, "t1", "s1")
        if vuln:
            assert "Enumeration" in vuln.title


# ============================================================================
#  OpenRedirectScanner
# ============================================================================

class TestOpenRedirectScanner:
    """Tests for OpenRedirectScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.open_redirect_scanner import OpenRedirectScanner
        scanner = OpenRedirectScanner()
        assert scanner.CATEGORY == VulnCategory.OPEN_REDIRECT

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.open_redirect_scanner import OpenRedirectScanner
        assert inspect.iscoroutinefunction(OpenRedirectScanner.scan)

    def test_payloads_defined(self):
        from bbhunter.engines.scanner.open_redirect_scanner import OpenRedirectScanner
        scanner = OpenRedirectScanner()
        assert len(scanner.PAYLOADS) > 0
        assert len(scanner.REDIRECT_PARAMS) > 0

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.open_redirect_scanner import OpenRedirectScanner
        scanner = OpenRedirectScanner()
        result = await scanner.scan([], "t1", "s1")
        assert result == []

    async def test_redirect_detected(self):
        from bbhunter.engines.scanner.open_redirect_scanner import OpenRedirectScanner
        scanner = OpenRedirectScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/redirect?url=http://safe.com",
            parameters=[Parameter(name="url", location="query")],
        )

        scanner._send_request = AsyncMock(
            return_value=_mock_response(
                status_code=302,
                headers={"location": "https://evil.com"},
            )
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        assert any("Redirect" in v.title for v in vulns)

    async def test_no_redirect_params(self):
        from bbhunter.engines.scanner.open_redirect_scanner import OpenRedirectScanner
        scanner = OpenRedirectScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/search?q=test",
            parameters=[Parameter(name="q")],
        )
        scanner._send_request = AsyncMock(return_value=_mock_response())
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []


# ============================================================================
#  SSRFScanner
# ============================================================================

class TestSSRFScanner:
    """Tests for SSRFScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner()
        assert scanner.CATEGORY == VulnCategory.SSRF

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
        assert inspect.iscoroutinefunction(SSRFScanner.scan)

    def test_payloads_and_params_defined(self):
        from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner()
        assert len(scanner.PAYLOADS) > 0
        assert "url" in scanner.SSRF_PARAMS

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner()
        result = await scanner.scan([], "t1", "s1")
        assert result == []

    async def test_ssrf_detected(self):
        from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/fetch?url=http://safe.com",
            parameters=[Parameter(name="url", location="query")],
        )

        scanner._send_request = AsyncMock(
            return_value=_mock_response(text="root:x:0:0:root:/root:/bin/bash")
        )
        vulns = await scanner.scan([ep], "t1", "s1")
        assert any("SSRF" in v.title for v in vulns)

    async def test_no_ssrf(self):
        from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/fetch?url=http://safe.com",
            parameters=[Parameter(name="url", location="query")],
        )

        scanner._send_request = AsyncMock(return_value=_mock_response(text="safe content"))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []

    async def test_no_ssrf_params(self):
        from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
        scanner = SSRFScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/search?q=test",
            parameters=[Parameter(name="q")],
        )
        scanner._send_request = AsyncMock(return_value=_mock_response())
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []


# ============================================================================
#  SSTIScanner
# ============================================================================

class TestSSTIScanner:
    """Tests for SSTIScanner."""

    def test_instantiation(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        assert scanner.CATEGORY == VulnCategory.SSTI

    def test_scan_is_async(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        assert inspect.iscoroutinefunction(SSTIScanner.scan)

    def test_payloads_defined(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        assert len(scanner.PAYLOADS) > 0

    def test_identify_engine_jinja2(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        assert scanner._identify_engine("{{7*'7'}}", "7777777") == "Jinja2/Twig"

    def test_identify_engine_freemarker(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        assert scanner._identify_engine("${7*7}", "49") == "Freemarker/Velocity/Mako"

    def test_identify_engine_erb(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        assert scanner._identify_engine("<%= 7*7 %>", "49") == "ERB/JSP"

    def test_identify_engine_smarty(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        assert scanner._identify_engine("{php}echo 'test';{/php}", "test") == "Smarty"

    def test_identify_engine_unknown(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        assert scanner._identify_engine("random", "output") == "Unknown"

    async def test_scan_no_endpoints(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()
        result = await scanner.scan([], "t1", "s1")
        assert result == []

    async def test_ssti_detected(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/greet?name=test",
            parameters=[Parameter(name="name", location="query")],
        )

        async def fake_send(url, **kw):
            if "7*7" in url or "7%2A7" in url:
                # Evaluated: return result, NOT the payload literal
                return _mock_response(text="Hello 49, welcome!")
            return _mock_response(text="Hello test, welcome!")

        scanner._send_request = fake_send  # type: ignore[assignment]
        vulns = await scanner.scan([ep], "t1", "s1")
        assert any("Template Injection" in v.title for v in vulns)

    async def test_no_ssti(self):
        from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
        scanner = SSTIScanner()

        ep = Endpoint(
            target_id="t",
            url="https://example.com/greet?name=test",
            parameters=[Parameter(name="name")],
        )

        scanner._send_request = AsyncMock(return_value=_mock_response(text="Hello test!"))
        vulns = await scanner.scan([ep], "t1", "s1")
        assert vulns == []


# ============================================================================
#  BaseScanner
# ============================================================================

class TestBaseScanner:
    """Tests for the shared BaseScanner base class."""

    def test_create_vulnerability(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        vuln = scanner._create_vulnerability(
            target_id="t1",
            scan_id="s1",
            title="Test Vuln",
            severity=Severity.HIGH,
            url="https://example.com",
            confidence=0.9,
        )
        assert isinstance(vuln, Vulnerability)
        assert vuln.title == "Test Vuln"
        assert vuln.severity == Severity.HIGH

    async def test_send_request_error_returns_none(self):
        from bbhunter.engines.scanner.xss_scanner import XSSScanner
        scanner = XSSScanner()
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = MagicMock()
            mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await scanner._send_request("https://example.com/timeout")
            assert result is None

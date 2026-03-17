"""
CORS Misconfiguration Scanner
===============================

Tests for:
- Wildcard origin reflection
- Null origin acceptance
- Subdomain origin acceptance
- Credential inclusion with permissive origins
"""

from __future__ import annotations

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class CORSScanner(BaseScanner):
    """CORS misconfiguration scanner."""

    CATEGORY = VulnCategory.CORS

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Test endpoints for CORS misconfigurations."""
        vulnerabilities: list[Vulnerability] = []

        for endpoint in endpoints:
            vulns = await self._test_cors(endpoint, target_id, scan_id)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_cors(
        self, endpoint: Endpoint, target_id: str, scan_id: str
    ) -> list[Vulnerability]:
        """Test a single endpoint for CORS issues."""
        vulns = []
        url = endpoint.url
        from urllib.parse import urlparse
        parsed = urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"

        # Test 1: Arbitrary origin reflection
        evil_origin = "https://evil-attacker.com"
        resp = await self._send_request(
            url, headers={"Origin": evil_origin}
        )
        if resp:
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")

            if acao == evil_origin:
                severity = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                vulns.append(self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title="CORS: Arbitrary Origin Reflection",
                    severity=severity,
                    url=url,
                    payload=f"Origin: {evil_origin}",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    description=(
                        "The server reflects arbitrary Origin headers in "
                        "Access-Control-Allow-Origin, allowing any website to "
                        "make cross-origin requests."
                    ),
                    impact=(
                        "Cross-origin data theft. If credentials are allowed, "
                        "an attacker's website can steal authenticated user data."
                    ),
                    remediation=(
                        "Whitelist specific trusted origins. "
                        "Never reflect arbitrary origins with credentials enabled."
                    ),
                    confidence=0.9,
                ))

            elif acao == "*":
                vulns.append(self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title="CORS: Wildcard Origin",
                    severity=Severity.LOW,
                    url=url,
                    evidence=f"ACAO: {acao}",
                    description="Wildcard (*) CORS policy allows any origin.",
                    confidence=0.85,
                ))

        # Test 2: Null origin
        resp = await self._send_request(url, headers={"Origin": "null"})
        if resp:
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "null":
                vulns.append(self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title="CORS: Null Origin Accepted",
                    severity=Severity.MEDIUM,
                    url=url,
                    payload="Origin: null",
                    evidence=f"ACAO: {acao}",
                    description=(
                        "The server accepts 'null' as a valid origin. "
                        "This can be exploited via sandboxed iframes."
                    ),
                    confidence=0.85,
                ))

        # Test 3: Subdomain takeover potential
        evil_subdomain = f"https://evil.{parsed.netloc}"
        resp = await self._send_request(url, headers={"Origin": evil_subdomain})
        if resp:
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == evil_subdomain:
                vulns.append(self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title="CORS: Subdomain Origin Accepted",
                    severity=Severity.MEDIUM,
                    url=url,
                    payload=f"Origin: {evil_subdomain}",
                    evidence=f"ACAO: {acao}",
                    description=(
                        "The server trusts subdomains. If a subdomain is compromisable "
                        "(XSS or takeover), CORS can be exploited."
                    ),
                    confidence=0.7,
                ))

        return vulns

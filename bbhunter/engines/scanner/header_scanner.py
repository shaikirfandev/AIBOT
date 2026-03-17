"""
Security Header Scanner
========================

Tests for missing or misconfigured security headers.
"""

from __future__ import annotations

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class HeaderScanner(BaseScanner):
    """Security header misconfiguration scanner."""

    CATEGORY = VulnCategory.OTHER

    SECURITY_HEADERS = {
        "strict-transport-security": {
            "severity": Severity.MEDIUM,
            "title": "Missing HSTS Header",
            "description": "HTTP Strict Transport Security (HSTS) header is not set.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
        },
        "x-content-type-options": {
            "severity": Severity.LOW,
            "title": "Missing X-Content-Type-Options",
            "description": "X-Content-Type-Options header is not set, allowing MIME sniffing.",
            "remediation": "Add 'X-Content-Type-Options: nosniff'",
        },
        "x-frame-options": {
            "severity": Severity.MEDIUM,
            "title": "Missing X-Frame-Options",
            "description": "X-Frame-Options not set, potentially vulnerable to clickjacking.",
            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
        },
        "content-security-policy": {
            "severity": Severity.MEDIUM,
            "title": "Missing Content-Security-Policy",
            "description": "CSP header is not configured, reducing XSS protection.",
            "remediation": "Implement a strict Content-Security-Policy header.",
        },
        "x-xss-protection": {
            "severity": Severity.LOW,
            "title": "Missing X-XSS-Protection",
            "description": "X-XSS-Protection header is not set.",
            "remediation": "Add 'X-XSS-Protection: 1; mode=block' (or use CSP instead).",
        },
        "referrer-policy": {
            "severity": Severity.LOW,
            "title": "Missing Referrer-Policy",
            "description": "Referrer-Policy not set, potentially leaking URLs to third parties.",
            "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
        },
        "permissions-policy": {
            "severity": Severity.LOW,
            "title": "Missing Permissions-Policy",
            "description": "Permissions-Policy (formerly Feature-Policy) not configured.",
            "remediation": "Configure Permissions-Policy to restrict browser features.",
        },
    }

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Check security headers on endpoints."""
        vulnerabilities: list[Vulnerability] = []
        checked_hosts = set()
        
        for endpoint in endpoints:
            from urllib.parse import urlparse
            host = urlparse(endpoint.url).netloc
            if host in checked_hosts:
                continue
            checked_hosts.add(host)

            resp = await self._send_request(endpoint.url)
            if resp is None:
                continue

            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, info in self.SECURITY_HEADERS.items():
                if header not in resp_headers:
                    vulnerabilities.append(self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=info["title"],
                        severity=info["severity"],
                        url=endpoint.url,
                        description=info["description"],
                        remediation=info["remediation"],
                        confidence=0.95,
                        evidence=f"Header '{header}' not found in response.",
                    ))

            # Check for information leakage headers
            info_headers = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]
            for h in info_headers:
                if h in resp_headers:
                    vulnerabilities.append(self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"Information Disclosure: {h} header",
                        severity=Severity.INFORMATIONAL,
                        url=endpoint.url,
                        evidence=f"{h}: {resp_headers[h]}",
                        description=f"The '{h}' header discloses technology information.",
                        remediation=f"Remove or obfuscate the '{h}' response header.",
                        confidence=0.95,
                    ))

        return vulnerabilities

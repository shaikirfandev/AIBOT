"""
Open Redirect Scanner
======================

Tests for URL redirect vulnerabilities.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class OpenRedirectScanner(BaseScanner):
    """Open redirect vulnerability scanner."""

    CATEGORY = VulnCategory.OPEN_REDIRECT

    REDIRECT_PARAMS = [
        "url", "redirect", "redirect_url", "redirect_uri", "return",
        "return_url", "returnTo", "next", "next_url", "dest",
        "destination", "go", "goto", "target", "link", "to",
        "out", "view", "callback", "continue", "return_path",
        "rurl", "r_url", "redir", "checkout_url", "login_url",
    ]

    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https://evil.com%00.target.com",
        "https://target.com@evil.com",
        "https://evil.com?.target.com",
        "https://evil.com#.target.com",
        "https://evil.com\\.target.com",
        "https://evil。com",  # Unicode dot
        "https:%2F%2Fevil.com",
        "///evil.com",
        "////evil.com",
        "https://evil.com/%2F%2F",
    ]

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan for open redirect vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        
        for endpoint in endpoints:
            for param in endpoint.parameters:
                if param.name.lower() in self.REDIRECT_PARAMS:
                    vulns = await self._test_redirect(
                        endpoint, param.name, target_id, scan_id
                    )
                    vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_redirect(
        self,
        endpoint: Endpoint,
        param_name: str,
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Test a parameter for open redirect."""
        vulns = []
        parsed = urlparse(endpoint.url)

        for payload in self.PAYLOADS:
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = await self._send_request(test_url)
            if resp is None:
                continue

            # Check for redirect
            location = resp.headers.get("location", "")
            
            if resp.status_code in (301, 302, 303, 307, 308):
                if "evil.com" in location:
                    vulns.append(self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"Open Redirect via '{param_name}'",
                        severity=Severity.MEDIUM,
                        url=endpoint.url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Location: {location}",
                        description=(
                            f"The '{param_name}' parameter allows redirecting users "
                            f"to arbitrary external domains."
                        ),
                        impact=(
                            "Phishing attacks, credential theft via fake login pages, "
                            "OAuth token theft, reputation damage."
                        ),
                        remediation=(
                            "Validate redirect URLs against a whitelist of allowed domains. "
                            "Use relative URLs for redirects. "
                            "Implement a redirect warning page."
                        ),
                        confidence=0.9,
                        steps=[
                            f"Request: {test_url}",
                            f"Response redirects to: {location}",
                        ],
                    ))
                    return vulns

            # Also check meta refresh and JavaScript redirects in body
            if resp.status_code == 200:
                body = resp.text.lower()
                if "evil.com" in body and (
                    "meta http-equiv" in body
                    or "window.location" in body
                    or "document.location" in body
                ):
                    vulns.append(self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"DOM-based Open Redirect via '{param_name}'",
                        severity=Severity.MEDIUM,
                        url=endpoint.url,
                        parameter=param_name,
                        payload=payload,
                        confidence=0.7,
                    ))
                    return vulns

        return vulns

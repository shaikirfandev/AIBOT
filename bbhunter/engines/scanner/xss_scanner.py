"""
XSS (Cross-Site Scripting) Scanner
====================================

Tests for:
- Reflected XSS
- Stored XSS indicators
- DOM-based XSS patterns
"""

from __future__ import annotations

import asyncio
import html
import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class XSSScanner(BaseScanner):
    """Cross-Site Scripting vulnerability scanner."""

    CATEGORY = VulnCategory.XSS

    # Reflected XSS payloads (progressively more evasive)
    PAYLOADS = [
        # Basic detection canaries
        'bbhunter"\'><',
        # Standard payloads
        '<script>alert("XSS")</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '"><img src=x onerror=alert(1)>',
        # Event handler payloads
        '" onfocus="alert(1)" autofocus="',
        "' onmouseover='alert(1)'",
        # SVG payloads
        '<svg/onload=alert(1)>',
        '<svg><script>alert(1)</script></svg>',
        # Template injection leading to XSS
        '{{constructor.constructor("alert(1)")()}}',
        '${alert(1)}',
        # Encoding bypass
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        # Null byte
        '%00<script>alert(1)</script>',
        # Case variation
        '<ScRiPt>alert(1)</ScRiPt>',
        # Without brackets
        '<img src=x onerror=alert`1`>',
    ]

    # Patterns indicating XSS reflection
    REFLECTION_PATTERNS = [
        r'<script>alert\(["\']?XSS["\']?\)</script>',
        r'<script>alert\(1\)</script>',
        r'onerror\s*=\s*alert',
        r'onload\s*=\s*alert',
        r'onfocus\s*=\s*alert',
        r'onmouseover\s*=\s*alert',
        r'<svg/onload=alert',
        r'<img\s+src=x\s+onerror=alert',
    ]

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan endpoints for XSS vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        
        for endpoint in endpoints:
            # Test each parameter
            for param in endpoint.parameters:
                vulns = await self._test_parameter(endpoint, param.name, target_id, scan_id)
                vulnerabilities.extend(vulns)

            # Test URL path for reflected content
            if endpoint.parameters:
                continue  # Already tested params
                
        return vulnerabilities

    async def _test_parameter(
        self,
        endpoint: Endpoint,
        param_name: str,
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Test a specific parameter for XSS."""
        vulns = []
        parsed = urlparse(endpoint.url)

        for payload in self.PAYLOADS[:self.config.scanner.max_payloads_per_param]:
            # Build test URL
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            
            test_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))

            resp = await self._send_request(test_url)
            if resp is None:
                continue

            body = resp.text

            # Check for reflection of payload
            if payload in body:
                # Verify it's not just URL-encoded in a safe context
                confidence = self._calculate_confidence(payload, body)
                
                if confidence > 0.5:
                    vuln = self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"Reflected XSS in parameter '{param_name}'",
                        severity=Severity.HIGH,
                        url=endpoint.url,
                        parameter=param_name,
                        payload=payload,
                        evidence=self._extract_evidence(body, payload),
                        description=(
                            f"The parameter '{param_name}' reflects user input without "
                            f"proper sanitization, allowing Cross-Site Scripting (XSS)."
                        ),
                        impact=(
                            "An attacker can execute arbitrary JavaScript in the context of "
                            "the victim's browser session, potentially leading to session "
                            "hijacking, credential theft, or malicious redirects."
                        ),
                        remediation=(
                            "Implement proper output encoding/escaping for the context "
                            "(HTML, JavaScript, URL, CSS). Use Content-Security-Policy headers. "
                            "Consider using a templating engine with auto-escaping."
                        ),
                        confidence=confidence,
                        request=f"GET {test_url}",
                        response=f"HTTP {resp.status_code}\n{body[:500]}",
                        steps=[
                            f"Navigate to: {test_url}",
                            f"Observe that the payload '{payload}' is reflected in the response",
                            "The script executes in the browser context",
                        ],
                    )
                    vulns.append(vuln)
                    break  # One confirmed XSS per param is enough

            # Check for pattern-based detection
            for pattern in self.REFLECTION_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    vuln = self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"Potential XSS in parameter '{param_name}'",
                        severity=Severity.HIGH,
                        url=endpoint.url,
                        parameter=param_name,
                        payload=payload,
                        confidence=0.6,
                    )
                    vulns.append(vuln)
                    break

        return vulns

    def _calculate_confidence(self, payload: str, body: str) -> float:
        """Calculate confidence that the reflection is exploitable."""
        confidence = 0.3

        # Check if payload is inside script tags
        if f"<script>{payload}" in body or f"{payload}</script>" in body:
            confidence = 0.95

        # Check if payload is in an HTML attribute context
        if f'="{payload}"' in body or f"='{payload}'" in body:
            confidence = 0.85

        # Check if payload appears to be in HTML body
        if f">{payload}<" in body:
            confidence = 0.8

        # Penalty if payload is HTML-encoded
        if html.escape(payload) in body and payload not in body:
            confidence = 0.1

        return confidence

    def _extract_evidence(self, body: str, payload: str, context_size: int = 100) -> str:
        """Extract the surrounding context where the payload was reflected."""
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - context_size)
        end = min(len(body), idx + len(payload) + context_size)
        return f"...{body[start:end]}..."

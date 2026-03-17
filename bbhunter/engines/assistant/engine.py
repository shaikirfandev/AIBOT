"""
Manual Testing Assistant
=========================

Assists human researchers with:
- Next attack vector suggestions
- Response analysis
- Payload recommendations
- Encoded data decoding
- JavaScript inspection
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Vulnerability, VulnCategory

logger = get_logger()


class ManualTestingAssistant:
    """
    AI-powered assistant for manual security testing.
    
    Provides contextual suggestions and analysis to help
    human researchers find and verify vulnerabilities.
    """

    def __init__(self):
        self.config = get_config()

    def suggest_attack_vectors(self, endpoint: Endpoint) -> list[dict[str, str]]:
        """
        Suggest attack vectors based on endpoint characteristics.
        
        Analyzes URL, parameters, headers, and technology stack
        to recommend the most promising attack vectors.
        """
        suggestions = []
        url_lower = endpoint.url.lower()
        param_names = [p.name.lower() for p in endpoint.parameters]

        # URL-based suggestions
        if any(kw in url_lower for kw in ["/api/", "/rest/", "/graphql"]):
            suggestions.append({
                "vector": "API Testing",
                "description": "Test for IDOR, mass assignment, rate limiting, authentication bypass",
                "priority": "high",
                "payloads": ["Try changing IDs", "Test without auth headers", "Check rate limits"],
            })

        if any(kw in url_lower for kw in ["/upload", "/file", "/import"]):
            suggestions.append({
                "vector": "File Upload",
                "description": "Test for unrestricted file upload, path traversal, XSS via filename",
                "priority": "high",
                "payloads": ["Upload .php/.jsp file", "Test double extensions", "Null byte in filename"],
            })

        if any(kw in url_lower for kw in ["/admin", "/dashboard", "/panel"]):
            suggestions.append({
                "vector": "Access Control",
                "description": "Test for authentication bypass, privilege escalation",
                "priority": "critical",
                "payloads": ["Remove auth cookies", "Try default creds", "Path traversal to admin"],
            })

        if any(kw in url_lower for kw in ["/login", "/auth", "/signin"]):
            suggestions.append({
                "vector": "Authentication Testing",
                "description": "Test for brute force, credential stuffing, MFA bypass",
                "priority": "high",
                "payloads": ["Test rate limiting", "Username enumeration", "Password reset flow"],
            })

        # Parameter-based suggestions
        id_params = [p for p in param_names if "id" in p or "user" in p or "account" in p]
        if id_params:
            suggestions.append({
                "vector": "IDOR",
                "description": f"Parameters {id_params} may be vulnerable to IDOR",
                "priority": "high",
                "payloads": ["Increment/decrement IDs", "Try other users' IDs", "Use UUIDs"],
            })

        url_params = [p for p in param_names if p in ("url", "redirect", "next", "return", "callback")]
        if url_params:
            suggestions.append({
                "vector": "Open Redirect / SSRF",
                "description": f"Parameters {url_params} accept URLs - test for redirect/SSRF",
                "priority": "high",
                "payloads": ["https://evil.com", "http://127.0.0.1", "//evil.com"],
            })

        search_params = [p for p in param_names if p in ("q", "search", "query", "s", "keyword")]
        if search_params:
            suggestions.append({
                "vector": "XSS / SQLi",
                "description": f"Search parameters {search_params} - test for injection",
                "priority": "medium",
                "payloads": ["<script>alert(1)</script>", "' OR 1=1--", "{{7*7}}"],
            })

        # Technology-based suggestions
        for tech in endpoint.technology:
            if "graphql" in tech.lower():
                suggestions.append({
                    "vector": "GraphQL Attacks",
                    "description": "Introspection, batching, nested queries, authorization bypass",
                    "priority": "high",
                    "payloads": [
                        '{"query":"{__schema{types{name}}}"}',
                        "Test for query depth limits",
                        "Try mutation without auth",
                    ],
                })

        if not suggestions:
            suggestions.append({
                "vector": "General Testing",
                "description": "Run standard OWASP tests on all parameters",
                "priority": "medium",
                "payloads": ["XSS probes", "SQLi probes", "Path traversal"],
            })

        return suggestions

    def analyze_response(self, response_text: str, status_code: int, headers: dict) -> dict[str, Any]:
        """
        Analyze an HTTP response for security-relevant information.
        """
        analysis = {
            "interesting_findings": [],
            "security_headers_present": [],
            "security_headers_missing": [],
            "technologies_detected": [],
            "potential_vulnerabilities": [],
            "encoded_data": [],
        }

        # Check for sensitive information in response
        sensitive_patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "ip_address": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            "api_key": r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})',
            "jwt_token": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            "aws_key": r'AKIA[0-9A-Z]{16}',
            "internal_path": r'(?:/home/|/var/|/etc/|C:\\|/usr/)[^\s<"\']+',
            "stack_trace": r'(?i)(traceback|stack trace|exception|error at)',
            "sql_query": r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.*\s+FROM\s+',
        }

        for name, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, response_text)
            if matches:
                analysis["interesting_findings"].append({
                    "type": name,
                    "count": len(matches),
                    "samples": matches[:3],
                })

        # Check security headers
        required_headers = [
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        ]
        headers_lower = {k.lower(): v for k, v in headers.items()}
        for h in required_headers:
            if h in headers_lower:
                analysis["security_headers_present"].append(h)
            else:
                analysis["security_headers_missing"].append(h)

        # Detect error conditions
        if status_code >= 500:
            analysis["potential_vulnerabilities"].append({
                "type": "Server Error",
                "detail": "500 errors may indicate injection or backend issues",
            })

        if status_code == 403:
            analysis["potential_vulnerabilities"].append({
                "type": "Access Control",
                "detail": "403 may be bypassable via path manipulation or header injection",
            })

        return analysis

    def decode_data(self, data: str) -> dict[str, Any]:
        """
        Attempt to decode encoded data through multiple methods.
        """
        results = {"original": data, "decodings": []}

        # Base64
        try:
            decoded = base64.b64decode(data).decode("utf-8", errors="replace")
            if decoded.isprintable() or len(decoded) > 5:
                results["decodings"].append({"method": "base64", "result": decoded})
                # Try to parse as JSON
                try:
                    results["decodings"][-1]["json"] = json.loads(decoded)
                except Exception:
                    pass
        except Exception:
            pass

        # URL decode
        try:
            decoded = urllib.parse.unquote(data)
            if decoded != data:
                results["decodings"].append({"method": "url_decode", "result": decoded})
        except Exception:
            pass

        # Double URL decode
        try:
            decoded = urllib.parse.unquote(urllib.parse.unquote(data))
            if decoded != data:
                results["decodings"].append({"method": "double_url_decode", "result": decoded})
        except Exception:
            pass

        # Hex decode
        try:
            decoded = bytes.fromhex(data.replace("0x", "").replace(" ", "")).decode("utf-8", errors="replace")
            results["decodings"].append({"method": "hex", "result": decoded})
        except Exception:
            pass

        # JWT decode
        if data.startswith("eyJ"):
            parts = data.split(".")
            if len(parts) >= 2:
                jwt_decoded = {}
                for i, name in enumerate(["header", "payload"]):
                    try:
                        padded = parts[i] + "=" * (4 - len(parts[i]) % 4)
                        jwt_decoded[name] = json.loads(base64.urlsafe_b64decode(padded))
                    except Exception:
                        pass
                if jwt_decoded:
                    results["decodings"].append({"method": "jwt", "result": jwt_decoded})

        return results

    def recommend_payloads(
        self,
        context: str,
        waf: str | None = None,
        previous_responses: list[str] | None = None,
    ) -> list[dict[str, str]]:
        """
        Recommend payloads based on context and previous attempts.
        
        Args:
            context: Description of what's being tested
            waf: Detected WAF
            previous_responses: Responses from previous payload attempts
        """
        recommendations = []

        context_lower = context.lower()

        if "xss" in context_lower or "script" in context_lower:
            recommendations.extend([
                {"payload": "<img src=x onerror=alert(1)>", "note": "Try event-handler based XSS"},
                {"payload": "<svg/onload=alert(1)>", "note": "SVG-based, often bypasses filters"},
                {"payload": "javascript:alert(1)", "note": "For href/src attributes"},
                {"payload": "'-alert(1)-'", "note": "For JavaScript context injection"},
            ])

        if "sql" in context_lower or "database" in context_lower:
            recommendations.extend([
                {"payload": "' OR 1=1--", "note": "Classic boolean test"},
                {"payload": "' UNION SELECT NULL--", "note": "Start UNION enumeration"},
                {"payload": "' AND SLEEP(5)--", "note": "Time-based blind detection"},
            ])

        if "redirect" in context_lower or "url" in context_lower:
            recommendations.extend([
                {"payload": "//evil.com", "note": "Protocol-relative redirect"},
                {"payload": "/\\evil.com", "note": "Backslash bypass"},
                {"payload": "https://evil.com%00.target.com", "note": "Null byte bypass"},
            ])

        if waf:
            recommendations.append({
                "payload": f"[WAF: {waf}] Try encoding + case variation",
                "note": f"Detected {waf} - use obfuscation techniques",
            })

        return recommendations

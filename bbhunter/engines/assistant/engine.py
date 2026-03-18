"""
Manual Testing Assistant Engine (v2 – Intelligence Upgrade)
============================================================

AI-powered assistant that helps a bug bounty hunter during manual testing:
- Context-aware attack vector suggestions with tech-specific playbooks
- Response analysis with sensitive-data pattern matching
- Data decoding (Base64, URL, JWT, hex, etc.)
- Payload recommendation ranked by historical effectiveness
- Business logic test suggestions based on endpoint patterns
- WAF-aware recommendations (delegates to PayloadEngine fingerprinting)
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, VulnCategory

logger = get_logger()


# ───────────────────────────────────────────────────────────
#  Technology-Specific Attack Playbooks
# ───────────────────────────────────────────────────────────

TECH_PLAYBOOKS: dict[str, list[dict[str, str]]] = {
    "graphql": [
        {"test": "Introspection query", "payload": '{"query":"{__schema{types{name,fields{name}}}}"}',
         "why": "Exposes entire API schema, field names, and types"},
        {"test": "Batch query abuse", "payload": '[{"query":"{ user(id:1){email} }"},{"query":"{ user(id:2){email} }"}]',
         "why": "Batch queries can bypass rate limiting for data extraction"},
        {"test": "Nested query DoS", "payload": '{"query":"{ a:__typename @include(if:true) }"}',
         "why": "Deep nesting can cause resource exhaustion"},
        {"test": "Field suggestion enumeration", "payload": '{"query":"{ usre }"}',
         "why": "Typos may trigger field suggestions revealing schema"},
        {"test": "Alias-based IDOR", "payload": '{"query":"{ a:user(id:1){id,email} b:user(id:2){id,email} }"}',
         "why": "Aliases allow fetching multiple users in one request"},
    ],
    "jwt": [
        {"test": "alg:none bypass", "payload": "Change header alg to 'none', remove signature",
         "why": "Some libraries accept unsigned tokens when alg=none"},
        {"test": "RS256→HS256 confusion", "payload": "Change alg from RS256 to HS256, sign with public key",
         "why": "Symmetric/asymmetric confusion allows forging tokens"},
        {"test": "kid injection", "payload": 'Set kid to "../../dev/null" or SQL payload',
         "why": "kid parameter may be used in file path or SQL query"},
        {"test": "jku/x5u header injection", "payload": "Set jku to attacker-controlled URL",
         "why": "Server may fetch JWK set from attacker URL"},
        {"test": "Weak secret brute-force", "payload": "Use jwt-cracker with common secrets",
         "why": "HS256 tokens with weak secrets can be forged"},
    ],
    "rest_api": [
        {"test": "HTTP method tampering", "payload": "Try PUT/PATCH/DELETE on GET endpoints",
         "why": "Missing method restrictions may allow state changes"},
        {"test": "Content-type switching", "payload": "Send JSON body as XML or form-data",
         "why": "Different parsers may handle input differently"},
        {"test": "API versioning bypass", "payload": "Change /v2/ to /v1/ in URL",
         "why": "Older API versions may lack security controls"},
        {"test": "Mass assignment", "payload": '{"role":"admin","email":"test@test.com"}',
         "why": "Extra fields in POST/PUT may update protected attributes"},
        {"test": "BOLA/IDOR", "payload": "Change numeric/UUID ID in resource path",
         "why": "Broken object level authorization allows accessing other users' data"},
    ],
    "wordpress": [
        {"test": "User enumeration", "payload": "/?author=1, /wp-json/wp/v2/users",
         "why": "Reveals valid usernames for brute-force attacks"},
        {"test": "XML-RPC brute force", "payload": "POST /xmlrpc.php with system.multicall",
         "why": "XML-RPC allows credential stuffing without rate limiting"},
        {"test": "Plugin file read", "payload": "/wp-content/debug.log",
         "why": "Debug logs may contain sensitive PHP errors"},
        {"test": "REST API exposure", "payload": "/wp-json/wp/v2/posts?status=draft",
         "why": "Draft/private posts may be accessible via API"},
    ],
    "oauth": [
        {"test": "Redirect URI manipulation", "payload": "Change redirect_uri to attacker domain",
         "why": "Code/token may be sent to attacker via open redirect"},
        {"test": "State parameter CSRF", "payload": "Remove or reuse state parameter",
         "why": "Missing state check enables CSRF on OAuth flow"},
        {"test": "Scope escalation", "payload": "Request scope=admin instead of scope=read",
         "why": "Server may not validate scope against client registration"},
        {"test": "Token reuse across clients", "payload": "Use token from client A on client B's API",
         "why": "Audience validation failure allows cross-client access"},
    ],
    "file_upload": [
        {"test": "Extension bypass", "payload": "file.php.jpg, file.pHp, file.php%00.jpg",
         "why": "Filter may only check last extension or be case-sensitive"},
        {"test": "Content-type bypass", "payload": "Set Content-Type: image/jpeg for PHP file",
         "why": "Server may rely on Content-Type header instead of actual content"},
        {"test": "SVG XSS", "payload": "Upload SVG with <script>alert(1)</script>",
         "why": "SVG files may execute JavaScript if served inline"},
        {"test": "Path traversal in filename", "payload": "../../../etc/cron.d/shell",
         "why": "Filename may be used in path without sanitization"},
    ],
}

# URL pattern → suggested attack categories
URL_ATTACK_MAP: list[tuple[str, list[dict[str, str]]]] = [
    (r"/api/", [
        {"category": "IDOR", "desc": "Test object ID manipulation", "priority": "high"},
        {"category": "Auth Bypass", "desc": "Test missing/weak authentication", "priority": "high"},
        {"category": "Mass Assignment", "desc": "Add extra fields in POST/PUT body", "priority": "medium"},
        {"category": "Rate Limit", "desc": "Check for rate limiting bypass", "priority": "medium"},
    ]),
    (r"/upload|/import|/file", [
        {"category": "File Upload", "desc": "Test malicious file upload", "priority": "high"},
        {"category": "Path Traversal", "desc": "Test filename path traversal", "priority": "high"},
        {"category": "SSRF", "desc": "Test URL-based file import for SSRF", "priority": "medium"},
    ]),
    (r"/admin|/manage|/dashboard", [
        {"category": "Auth Bypass", "desc": "Test access without admin credentials", "priority": "critical"},
        {"category": "Privilege Escalation", "desc": "Test horizontal/vertical privesc", "priority": "critical"},
        {"category": "CSRF", "desc": "Test state-changing actions without CSRF token", "priority": "high"},
    ]),
    (r"/login|/auth|/signin|/oauth", [
        {"category": "Brute Force", "desc": "Check rate limiting on login attempts", "priority": "high"},
        {"category": "Username Enumeration", "desc": "Different error messages for valid/invalid users", "priority": "medium"},
        {"category": "2FA Bypass", "desc": "Test 2FA bypass techniques", "priority": "high"},
        {"category": "OAuth Issues", "desc": "Test redirect_uri, state, scope manipulation", "priority": "high"},
    ]),
    (r"/search|/filter|\?q=|\?query=", [
        {"category": "XSS", "desc": "Search term reflected in page", "priority": "high"},
        {"category": "SQLi", "desc": "Search may query database directly", "priority": "high"},
        {"category": "Information Disclosure", "desc": "Search may reveal hidden records", "priority": "medium"},
    ]),
    (r"/redirect|/goto|/return|/next|/url=|/link=", [
        {"category": "Open Redirect", "desc": "Test external URL redirect", "priority": "high"},
        {"category": "SSRF", "desc": "URL parameter may fetch internal resources", "priority": "high"},
    ]),
    (r"/export|/download|/report", [
        {"category": "IDOR", "desc": "Access other users' exports", "priority": "high"},
        {"category": "Path Traversal", "desc": "Manipulate file path in export", "priority": "high"},
        {"category": "Injection", "desc": "CSV injection / formula injection in exports", "priority": "medium"},
    ]),
    (r"/graphql", [
        {"category": "GraphQL", "desc": "Introspection, batching, nested query DoS", "priority": "critical"},
    ]),
    (r"/webhook|/callback|/notify", [
        {"category": "SSRF", "desc": "Webhook URL may fetch internal resources", "priority": "high"},
        {"category": "Injection", "desc": "Callback data may be injected into backend", "priority": "medium"},
    ]),
    (r"/pay|/checkout|/cart|/order|/price", [
        {"category": "Business Logic", "desc": "Price manipulation, quantity tampering", "priority": "critical"},
        {"category": "IDOR", "desc": "Access other users' orders", "priority": "high"},
        {"category": "Race Condition", "desc": "Double-spend or coupon reuse", "priority": "high"},
    ]),
    (r"/profile|/account|/settings|/user", [
        {"category": "IDOR", "desc": "Access other users' profiles", "priority": "high"},
        {"category": "CSRF", "desc": "Change email/password without CSRF protection", "priority": "high"},
        {"category": "Mass Assignment", "desc": "Update role/permissions via hidden fields", "priority": "high"},
    ]),
]

# Parameter name patterns → attack type
PARAM_ATTACK_MAP: list[tuple[str, str, str]] = [
    (r"^id$|_id$|^uid$|^user_id$", "IDOR", "Manipulate ID to access other resources"),
    (r"^url$|^link$|^src$|^href$|^dest$|^target$|^uri$", "SSRF / Open Redirect",
     "URL parameter — test for SSRF and open redirect"),
    (r"^redirect|^return|^next|^goto|^continue", "Open Redirect",
     "Redirect parameter — test external URL injection"),
    (r"^q$|^search|^query|^keyword|^term", "XSS / SQLi",
     "Search/query parameter — test for reflection and injection"),
    (r"^page$|^p$|^offset|^limit|^skip|^count", "SQLi / IDOR",
     "Pagination — test for injection and access control bypass"),
    (r"^file|^path|^doc|^template|^include|^lang", "Path Traversal / LFI",
     "File parameter — test directory traversal"),
    (r"^token|^key|^api_key|^secret|^auth", "Information Disclosure",
     "Secret parameter — check if exposed or guessable"),
    (r"^callback|^jsonp|^cb$", "XSS",
     "JSONP callback — test for JavaScript injection"),
    (r"^email|^phone|^name|^address", "Information Disclosure / IDOR",
     "PII parameter — test for mass enumeration"),
    (r"^amount|^price|^qty|^quantity|^total", "Business Logic",
     "Financial parameter — test price/quantity manipulation"),
]

# Sensitive data patterns for response analysis
SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Email address", "medium"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Internal IP address", "medium"),
    (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "AWS Access Key", "critical"),
    (r"(?:key|token|secret|password|api_key|apikey|auth)[\s]*[=:]\s*['\"][^'\"]{8,}", "Potential secret/key", "high"),
    (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+", "JWT token", "high"),
    (r"/(?:home|root|var|etc|usr|opt|tmp)/[^\s'\"<>]+", "Internal file path", "medium"),
    (r"(?:Traceback|Exception|Error|stack trace|at \w+\.\w+\()", "Stack trace / debug info", "medium"),
    (r"(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)\s+\w+\s+(?:FROM|INTO|SET|TABLE)", "SQL query fragment", "high"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private key", "critical"),
    (r"(?:mongodb|postgres|mysql|redis)://[^\s'\"]+", "Database connection string", "critical"),
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI API key", "critical"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token", "critical"),
    (r"xox[bpras]-[a-zA-Z0-9-]+", "Slack token", "critical"),
    (r"Bearer\s+[a-zA-Z0-9._~+/=-]{20,}", "Bearer token", "high"),
    (r"(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{4,}", "Hardcoded password", "critical"),
]

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {"required": True, "issue": "Missing HSTS — vulnerable to downgrade attacks"},
    "Content-Security-Policy": {"required": True, "issue": "Missing CSP — XSS impact amplified"},
    "X-Content-Type-Options": {"required": True, "issue": "Missing X-Content-Type-Options — MIME sniffing risk"},
    "X-Frame-Options": {"required": True, "issue": "Missing X-Frame-Options — clickjacking risk"},
    "X-XSS-Protection": {"required": False, "issue": "Missing X-XSS-Protection (legacy browsers)"},
    "Referrer-Policy": {"required": True, "issue": "Missing Referrer-Policy — information leakage"},
    "Permissions-Policy": {"required": False, "issue": "Missing Permissions-Policy"},
    "Cache-Control": {"required": False, "issue": "Check Cache-Control for sensitive responses"},
}

# CORS misconfig patterns
CORS_CHECKS = [
    {"origin": "https://evil.com", "desc": "Arbitrary origin reflection"},
    {"origin": "null", "desc": "null origin accepted"},
    {"origin": "https://target.com.evil.com", "desc": "Subdomain suffix bypass"},
    {"origin": "https://evil-target.com", "desc": "Prefix bypass"},
]


class ManualTestingAssistant:
    """
    AI-powered assistant for manual bug bounty testing.

    Provides intelligent suggestions based on endpoint context,
    technology stack, historical effectiveness, and response analysis.
    """

    def __init__(self):
        self.config = get_config()
        self._learning_engine: Any = None
        self._payload_engine: Any = None

    def set_learning_engine(self, engine: Any):
        """Inject LearningEngine for data-driven recommendations."""
        self._learning_engine = engine

    def set_payload_engine(self, engine: Any):
        """Inject PayloadEngine for WAF-aware payload generation."""
        self._payload_engine = engine

    # ───────────────────────────────────────────────────────
    #  Attack Vector Suggestions
    # ───────────────────────────────────────────────────────

    def suggest_attack_vectors(self, endpoint: Endpoint) -> list[dict[str, Any]]:
        """
        Suggest attack vectors for a given endpoint.

        Combines URL patterns, parameter analysis, technology playbooks,
        and historical learning data.
        """
        suggestions: list[dict[str, Any]] = []

        # 1) URL-pattern-based suggestions
        for pattern, attacks in URL_ATTACK_MAP:
            if re.search(pattern, endpoint.url, re.IGNORECASE):
                for attack in attacks:
                    suggestions.append({
                        "type": "url_pattern",
                        "source": pattern,
                        **attack,
                    })

        # 2) Parameter-based suggestions
        for param in endpoint.parameters:
            for pattern, category, desc in PARAM_ATTACK_MAP:
                if re.search(pattern, param.name, re.IGNORECASE):
                    suggestions.append({
                        "type": "parameter",
                        "parameter": param.name,
                        "category": category,
                        "desc": desc,
                        "priority": "high",
                    })

        # 3) Technology-specific playbooks
        techs = [t.lower() for t in endpoint.technology]
        for tech_key, playbook in TECH_PLAYBOOKS.items():
            if any(tech_key in t for t in techs) or tech_key in endpoint.url.lower():
                for item in playbook:
                    suggestions.append({
                        "type": "tech_playbook",
                        "technology": tech_key,
                        "test": item["test"],
                        "payload": item["payload"],
                        "why": item["why"],
                        "priority": "high",
                    })

        # 4) GraphQL auto-detect
        if "/graphql" in endpoint.url.lower() or "graphql" in techs:
            if not any(s.get("technology") == "graphql" for s in suggestions):
                for item in TECH_PLAYBOOKS["graphql"]:
                    suggestions.append({
                        "type": "tech_playbook", "technology": "graphql",
                        "test": item["test"], "payload": item["payload"],
                        "why": item["why"], "priority": "critical",
                    })

        # 5) Business logic tests based on endpoint context
        suggestions.extend(self._business_logic_suggestions(endpoint))

        # 6) Rank by historical effectiveness
        if self._learning_engine:
            suggestions = self._rank_by_learning(suggestions)

        # Deduplicate by category+desc
        seen = set()
        unique: list[dict[str, Any]] = []
        for s in suggestions:
            key = f"{s.get('category', '')}:{s.get('desc', s.get('test', ''))}"
            if key not in seen:
                seen.add(key)
                unique.append(s)

        return unique

    def _business_logic_suggestions(self, endpoint: Endpoint) -> list[dict[str, Any]]:
        """Suggest business logic tests based on endpoint semantics."""
        suggestions: list[dict[str, Any]] = []
        url_l = endpoint.url.lower()
        method = endpoint.method.upper()

        # Payment / checkout flows
        if any(kw in url_l for kw in ["/pay", "/checkout", "/cart", "/order", "/price"]):
            suggestions.append({
                "type": "business_logic", "category": "Price Manipulation",
                "desc": "Modify price/amount/discount parameters to negative or zero values",
                "priority": "critical",
            })
            suggestions.append({
                "type": "business_logic", "category": "Race Condition",
                "desc": "Send concurrent requests to exploit race conditions (double-spend, coupon reuse)",
                "priority": "high",
            })

        # Account management
        if any(kw in url_l for kw in ["/register", "/signup", "/invite"]):
            suggestions.append({
                "type": "business_logic", "category": "Account Manipulation",
                "desc": "Test email verification bypass, referral abuse, invite-only bypass",
                "priority": "high",
            })

        # Delete / destructive operations
        if method == "DELETE" or "delete" in url_l:
            suggestions.append({
                "type": "business_logic", "category": "Authorization",
                "desc": "Verify delete requires proper authorization — test deleting other users' resources",
                "priority": "critical",
            })

        # Voting / rating / review
        if any(kw in url_l for kw in ["/vote", "/rate", "/review", "/like", "/follow"]):
            suggestions.append({
                "type": "business_logic", "category": "Abuse",
                "desc": "Test for vote manipulation, self-review, rate limiting bypass",
                "priority": "medium",
            })

        # 2FA / MFA
        if any(kw in url_l for kw in ["/2fa", "/mfa", "/otp", "/verify"]):
            suggestions.append({
                "type": "business_logic", "category": "2FA Bypass",
                "desc": "Test OTP brute-force, code reuse, response manipulation, direct page access",
                "priority": "critical",
            })

        return suggestions

    def _rank_by_learning(self, suggestions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Re-order suggestions: put historically effective categories first."""
        try:
            trends = self._learning_engine.get_trends(window_days=90)
            top_cats = trends.get("category_distribution", {})
            if not top_cats:
                return suggestions

            def score(s: dict) -> int:
                cat = s.get("category", "").lower()
                for top_cat, count in top_cats.items():
                    if top_cat in cat.lower() or cat.lower() in top_cat:
                        return count
                return 0

            return sorted(suggestions, key=score, reverse=True)
        except Exception as exc:
            logger.debug(f"Attack vector sorting failed: {exc}")
            return suggestions

    # ───────────────────────────────────────────────────────
    #  Response Analysis
    # ───────────────────────────────────────────────────────

    def analyze_response(
        self,
        response_body: str,
        response_headers: dict[str, str] | None = None,
        status_code: int = 200,
    ) -> dict[str, Any]:
        """
        Analyze an HTTP response for security-relevant patterns.
        """
        findings: list[dict[str, str]] = []

        # 1) Sensitive data in body
        for pattern, label, severity in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, response_body[:50_000])
            if matches:
                findings.append({
                    "type": "sensitive_data",
                    "label": label,
                    "severity": severity,
                    "matches": matches[:5],
                    "count": len(matches),
                })

        # 2) Security header analysis
        header_issues: list[dict[str, str]] = []
        if response_headers:
            for header, info in SECURITY_HEADERS.items():
                found = any(h.lower() == header.lower() for h in response_headers)
                if not found and info["required"]:
                    header_issues.append({"header": header, "issue": info["issue"]})

            # CORS check
            acao = response_headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                header_issues.append({
                    "header": "Access-Control-Allow-Origin",
                    "issue": "Wildcard CORS — any origin can read responses",
                })
            acac = response_headers.get("Access-Control-Allow-Credentials", "")
            if acac.lower() == "true" and acao and acao != "*":
                header_issues.append({
                    "header": "CORS+Credentials",
                    "issue": f"CORS allows credentials from {acao} — test origin reflection",
                })

        # 3) Error / debug detection
        debug_indicators = []
        debug_patterns = [
            (r"(?:Traceback|stack trace)", "Stack trace leaked"),
            (r"(?:DEBUG|DEVELOPMENT)\s*(?:=|:)\s*(?:True|1|on)", "Debug mode enabled"),
            (r"(?:Laravel|Django|Rails|Express|Spring)\s+(?:error|exception)", "Framework error"),
            (r"phpinfo\(\)", "phpinfo() exposed"),
            (r"<!-- .*(?:TODO|FIXME|HACK|BUG)", "Developer comment in HTML"),
        ]
        for pattern, label in debug_patterns:
            if re.search(pattern, response_body[:50_000], re.IGNORECASE):
                debug_indicators.append(label)

        # 4) WAF detection (delegate to PayloadEngine if injected)
        waf_detected = None
        if self._payload_engine and response_headers:
            try:
                waf_detected = self._payload_engine.fingerprint_waf(
                    headers=response_headers, body=response_body[:5000], status_code=status_code,
                )
            except Exception as exc:
                logger.debug(f"WAF fingerprinting failed: {exc}")

        return {
            "sensitive_data": findings,
            "security_headers": header_issues,
            "debug_indicators": debug_indicators,
            "waf_detected": waf_detected,
            "risk_score": self._calculate_risk_score(findings, header_issues, debug_indicators),
        }

    def _calculate_risk_score(
        self,
        findings: list[dict],
        header_issues: list[dict],
        debug_indicators: list[str],
    ) -> float:
        """Calculate a 0-10 risk score from response analysis."""
        score = 0.0
        severity_weight = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}
        for f in findings:
            score += severity_weight.get(f.get("severity", "low"), 0.5)
        score += len(header_issues) * 0.5
        score += len(debug_indicators) * 1.0
        return min(round(score, 1), 10.0)

    # ───────────────────────────────────────────────────────
    #  Data Decoding
    # ───────────────────────────────────────────────────────

    def decode_data(self, data: str) -> dict[str, Any]:
        """Attempt to decode encoded data through multiple methods."""
        results: dict[str, Any] = {"original": data, "decodings": []}

        # Base64
        try:
            decoded = base64.b64decode(data).decode("utf-8", errors="replace")
            if decoded.isprintable() or len(decoded) > 5:
                entry: dict[str, Any] = {"method": "base64", "result": decoded}
                try:
                    entry["json"] = json.loads(decoded)
                except Exception as exc:
                    logger.debug(f"Base64 decoded content is not JSON: {exc}")
                results["decodings"].append(entry)
        except Exception as exc:
            logger.debug(f"Base64 decode failed: {exc}")

        # URL decode
        try:
            decoded = urllib.parse.unquote(data)
            if decoded != data:
                results["decodings"].append({"method": "url_decode", "result": decoded})
        except Exception as exc:
            logger.debug(f"URL decode failed: {exc}")

        # Double URL decode
        try:
            decoded = urllib.parse.unquote(urllib.parse.unquote(data))
            if decoded != data:
                results["decodings"].append({"method": "double_url_decode", "result": decoded})
        except Exception as exc:
            logger.debug(f"Double URL decode failed: {exc}")

        # Hex decode
        try:
            decoded = bytes.fromhex(data.replace("0x", "").replace(" ", "")).decode("utf-8", errors="replace")
            results["decodings"].append({"method": "hex", "result": decoded})
        except Exception as exc:
            logger.debug(f"Hex decode failed: {exc}")

        # JWT decode
        if data.startswith("eyJ"):
            parts = data.split(".")
            if len(parts) >= 2:
                jwt_decoded: dict[str, Any] = {}
                for i, name in enumerate(["header", "payload"]):
                    try:
                        padded = parts[i] + "=" * (4 - len(parts[i]) % 4)
                        jwt_decoded[name] = json.loads(base64.urlsafe_b64decode(padded))
                    except Exception as exc:
                        logger.debug(f"JWT {name} decode failed: {exc}")
                if jwt_decoded:
                    results["decodings"].append({"method": "jwt", "result": jwt_decoded})
                    # Security analysis of JWT
                    header = jwt_decoded.get("header", {})
                    if header.get("alg", "").lower() in ("none", "hs256"):
                        results["jwt_warning"] = f"Weak algorithm: {header.get('alg')}"

        return results

    # ───────────────────────────────────────────────────────
    #  Payload Recommendation
    # ───────────────────────────────────────────────────────

    def recommend_payloads(
        self,
        context: str,
        waf: str | None = None,
        previous_responses: list[str] | None = None,
    ) -> list[dict[str, str]]:
        """
        Recommend payloads based on context, WAF, and previous attempts.

        If PayloadEngine and LearningEngine are available, uses ranked payloads
        from historical data.
        """
        recommendations: list[dict[str, str]] = []
        context_lower = context.lower()

        # Delegate to PayloadEngine for WAF-specific payloads
        if self._payload_engine and waf:
            try:
                waf_payloads = self._payload_engine._waf_specific_bypass(waf, "xss")
                for p in waf_payloads[:3]:
                    recommendations.append({"payload": p, "note": f"WAF bypass for {waf}"})
            except Exception as exc:
                logger.debug(f"WAF-specific payload generation failed: {exc}")

        if "xss" in context_lower or "script" in context_lower:
            recommendations.extend([
                {"payload": "<img src=x onerror=alert(1)>", "note": "Event-handler based — bypasses script blocks"},
                {"payload": "<svg/onload=alert(1)>", "note": "SVG-based — often bypasses tag filters"},
                {"payload": "javascript:alert(1)", "note": "For href/src attributes"},
                {"payload": "'-alert(1)-'", "note": "JavaScript context injection"},
                {"payload": "{{constructor.constructor('alert(1)')()}}", "note": "Template injection → XSS"},
            ])

        if "sql" in context_lower or "database" in context_lower:
            recommendations.extend([
                {"payload": "' OR 1=1--", "note": "Classic boolean test"},
                {"payload": "' UNION SELECT NULL--", "note": "Start UNION enumeration"},
                {"payload": "' AND SLEEP(5)--", "note": "Time-based blind detection"},
                {"payload": "' AND extractvalue(1,concat(0x7e,version()))--", "note": "XML error-based extraction"},
            ])

        if "redirect" in context_lower or "url" in context_lower:
            recommendations.extend([
                {"payload": "//evil.com", "note": "Protocol-relative redirect"},
                {"payload": "/\\evil.com", "note": "Backslash bypass"},
                {"payload": "https://evil.com%00.target.com", "note": "Null byte bypass"},
            ])

        if "ssti" in context_lower or "template" in context_lower:
            recommendations.extend([
                {"payload": "{{7*7}}", "note": "Jinja2/Twig detection — expect 49"},
                {"payload": "${7*7}", "note": "Mako/Freemarker detection"},
                {"payload": "<%= 7*7 %>", "note": "ERB detection"},
            ])

        # Analyze previous responses (if provided) to adapt recommendations
        if previous_responses and self._payload_engine:
            blocked_chars = set()
            for resp in previous_responses:
                for ch in ['<', '>', '"', "'", '(', ')', '{', '}']:
                    if ch not in resp:
                        blocked_chars.add(ch)
            if blocked_chars:
                recommendations.append({
                    "payload": f"[ADAPTIVE] Filtered chars: {', '.join(blocked_chars)}",
                    "note": "Use encoding chains or alternative syntax to bypass",
                })

        return recommendations

    # ───────────────────────────────────────────────────────
    #  CORS Testing Helper
    # ───────────────────────────────────────────────────────

    def suggest_cors_tests(self, target_url: str) -> list[dict[str, str]]:
        """Generate CORS misconfiguration test cases for a URL."""
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc

        tests: list[dict[str, str]] = []
        for check in CORS_CHECKS:
            origin = check["origin"].replace("target.com", domain)
            tests.append({
                "origin": origin,
                "desc": check["desc"],
                "curl": f'curl -s -H "Origin: {origin}" -I {target_url} | grep -i "access-control"',
            })

        # Subdomain wildcard
        parts = domain.split(".")
        if len(parts) >= 2:
            base = ".".join(parts[-2:])
            tests.append({
                "origin": f"https://evil.{base}",
                "desc": "Subdomain trust — is any subdomain origin accepted?",
                "curl": f'curl -s -H "Origin: https://evil.{base}" -I {target_url} | grep -i "access-control"',
            })

        return tests

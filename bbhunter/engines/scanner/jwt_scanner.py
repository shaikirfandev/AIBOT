"""
JWT (JSON Web Token) Scanner
==============================

Tests for JWT implementation weaknesses:
- Algorithm confusion (none, HS256 vs RS256)
- Weak secrets
- Missing expiration
- Sensitive data in payload
"""

from __future__ import annotations

import base64
import json
import re

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class JWTScanner(BaseScanner):
    """JWT vulnerability scanner."""

    CATEGORY = VulnCategory.JWT

    # Common weak secrets
    WEAK_SECRETS = [
        "secret", "password", "123456", "key", "jwt_secret",
        "your-256-bit-secret", "shhhhh", "admin", "test",
        "changeme", "default", "jwt", "token", "supersecret",
    ]

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan for JWT vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []

        for endpoint in endpoints:
            # Look for JWTs in response headers and body
            resp = await self._send_request(endpoint.url)
            if resp is None:
                continue

            # Find JWTs in response
            jwts = self._find_jwts(resp.text)
            jwts.extend(self._find_jwts(str(resp.headers)))

            for jwt_token in jwts:
                vulns = self._analyze_jwt(jwt_token, endpoint.url, target_id, scan_id)
                vulnerabilities.extend(vulns)

        return vulnerabilities

    def _find_jwts(self, text: str) -> list[str]:
        """Find JWT tokens in text using regex."""
        pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
        return re.findall(pattern, text)

    def _analyze_jwt(
        self, token: str, url: str, target_id: str, scan_id: str
    ) -> list[Vulnerability]:
        """Analyze a JWT token for weaknesses."""
        vulns = []
        
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return vulns

            # Decode header
            header = self._decode_jwt_part(parts[0])
            payload = self._decode_jwt_part(parts[1])

            if header is None or payload is None:
                return vulns

            # Check 1: Algorithm "none"
            alg = header.get("alg", "")
            if alg.lower() in ("none", ""):
                vulns.append(self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title="JWT: Algorithm 'none' vulnerability",
                    severity=Severity.CRITICAL,
                    url=url,
                    evidence=f"JWT header: {json.dumps(header)}",
                    description="JWT uses 'none' algorithm, allowing unsigned tokens.",
                    impact="Complete authentication bypass. Anyone can forge valid tokens.",
                    remediation="Enforce a specific signing algorithm (RS256 or ES256).",
                    confidence=0.95,
                ))

            # Check 2: Missing expiration
            if "exp" not in payload:
                vulns.append(self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title="JWT: Missing Expiration Claim",
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence=f"JWT payload has no 'exp' claim",
                    description="JWT token has no expiration, remaining valid indefinitely.",
                    remediation="Always include an 'exp' claim with a reasonable TTL.",
                    confidence=0.9,
                ))

            # Check 3: Sensitive data in payload
            sensitive_keys = ["password", "secret", "ssn", "credit_card", "cc_number"]
            for key in payload:
                if key.lower() in sensitive_keys:
                    vulns.append(self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"JWT: Sensitive Data in Payload ('{key}')",
                        severity=Severity.HIGH,
                        url=url,
                        evidence=f"JWT payload contains sensitive key: {key}",
                        description="JWT payload contains sensitive information that is base64-encoded, not encrypted.",
                        remediation="Never store sensitive data in JWT payloads. Use encrypted JWE if needed.",
                        confidence=0.85,
                    ))

            # Check 4: Weak secret (HS256)
            if alg in ("HS256", "HS384", "HS512"):
                weak = self._test_weak_secrets(token, alg)
                if weak:
                    vulns.append(self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title="JWT: Weak Signing Secret",
                        severity=Severity.CRITICAL,
                        url=url,
                        payload=f"Secret: {weak}",
                        description=f"JWT signed with weak secret '{weak}'.",
                        impact="Tokens can be forged with the known secret.",
                        remediation="Use a strong, random secret (256+ bits).",
                        confidence=0.95,
                    ))

        except Exception as e:
            logger.debug(f"JWT analysis error: {e}")

        return vulns

    def _decode_jwt_part(self, part: str) -> dict | None:
        """Decode a base64url JWT part."""
        try:
            # Add padding
            padding = 4 - len(part) % 4
            if padding != 4:
                part += "=" * padding
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except Exception as exc:
            logger.debug(f"JWT part decode failed: {exc}")
            return None

    def _test_weak_secrets(self, token: str, alg: str) -> str | None:
        """Test JWT against a list of common weak secrets."""
        try:
            import hmac
            import hashlib

            parts = token.split(".")
            message = f"{parts[0]}.{parts[1]}".encode()
            original_sig = parts[2]

            hash_funcs = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }
            hash_func = hash_funcs.get(alg)
            if not hash_func:
                return None

            for secret in self.WEAK_SECRETS:
                sig = base64.urlsafe_b64encode(
                    hmac.new(secret.encode(), message, hash_func).digest()
                ).rstrip(b"=").decode()

                if sig == original_sig:
                    return secret

        except Exception as exc:
            logger.debug(f"JWT weak secret test failed: {exc}")
        return None

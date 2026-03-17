"""
Authentication Scanner
=======================

Tests for:
- Default credentials
- Username enumeration
- Account lockout policy
- Password policy weaknesses
- Authentication bypass
"""

from __future__ import annotations

from urllib.parse import urlparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class AuthScanner(BaseScanner):
    """Authentication vulnerability scanner."""

    CATEGORY = VulnCategory.AUTH_BYPASS

    # Common default credentials
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("guest", "guest"),
        ("admin", "admin123"),
        ("administrator", "administrator"),
    ]

    AUTH_PATHS = [
        "/login", "/signin", "/auth", "/authenticate",
        "/admin/login", "/admin", "/wp-login.php",
        "/user/login", "/account/login", "/api/login",
        "/api/auth", "/api/v1/auth", "/oauth/token",
    ]

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan for authentication vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        
        # Find login endpoints
        login_endpoints = [
            ep for ep in endpoints
            if any(path in ep.url.lower() for path in self.AUTH_PATHS)
        ]

        if not login_endpoints and endpoints:
            # Try discovering login endpoints
            parsed = urlparse(endpoints[0].url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in self.AUTH_PATHS:
                url = f"{base}{path}"
                resp = await self._send_request(url)
                if resp and resp.status_code in (200, 401, 403):
                    login_endpoints.append(Endpoint(
                        target_id=target_id,
                        url=url,
                        status_code=resp.status_code,
                    ))

        for ep in login_endpoints:
            # Test username enumeration
            enum_vuln = await self._test_username_enumeration(ep, target_id, scan_id)
            if enum_vuln:
                vulnerabilities.append(enum_vuln)

            # Test default credentials (limited, not brute force)
            cred_vuln = await self._test_default_creds(ep, target_id, scan_id)
            if cred_vuln:
                vulnerabilities.append(cred_vuln)

        return vulnerabilities

    async def _test_username_enumeration(
        self, endpoint: Endpoint, target_id: str, scan_id: str
    ) -> Vulnerability | None:
        """Test for username enumeration via response differences."""
        
        # Try a known-likely username and a random one
        valid_attempt = await self._send_request(
            endpoint.url,
            method="POST",
            data={"username": "admin", "password": "wrongpassword12345"},
        )
        invalid_attempt = await self._send_request(
            endpoint.url,
            method="POST",
            data={"username": "nonexistent_user_xyz_12345", "password": "wrongpassword12345"},
        )

        if valid_attempt and invalid_attempt:
            # Check for different response lengths or messages
            if (
                valid_attempt.status_code == invalid_attempt.status_code
                and abs(len(valid_attempt.text) - len(invalid_attempt.text)) > 20
            ):
                return self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title="Username Enumeration via Login Response",
                    severity=Severity.LOW,
                    url=endpoint.url,
                    description=(
                        "The login endpoint returns different responses for valid "
                        "vs invalid usernames, allowing attackers to enumerate accounts."
                    ),
                    evidence=(
                        f"Response length for 'admin': {len(valid_attempt.text)}, "
                        f"Response length for random user: {len(invalid_attempt.text)}"
                    ),
                    remediation="Use generic error messages like 'Invalid credentials'.",
                    confidence=0.6,
                )
        return None

    async def _test_default_creds(
        self, endpoint: Endpoint, target_id: str, scan_id: str
    ) -> Vulnerability | None:
        """Test a limited set of default credentials (NOT brute force)."""
        # Only test a few common defaults
        for username, password in self.DEFAULT_CREDS[:5]:
            resp = await self._send_request(
                endpoint.url,
                method="POST",
                data={"username": username, "password": password},
            )
            
            if resp and resp.status_code in (200, 302):
                # Check for success indicators
                body = resp.text.lower()
                location = resp.headers.get("location", "").lower()
                
                success_indicators = [
                    "dashboard", "welcome", "profile", "logout",
                    "set-cookie" in str(resp.headers).lower() and "session" in str(resp.headers).lower(),
                ]
                
                redirect_indicators = [
                    "dashboard" in location,
                    "admin" in location,
                    "home" in location,
                ]
                
                if any(ind in body for ind in ["dashboard", "welcome", "profile"]) or any(redirect_indicators):
                    return self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"Default Credentials: {username}/{password}",
                        severity=Severity.CRITICAL,
                        url=endpoint.url,
                        payload=f"{username}:{password}",
                        description=f"Login successful with default credentials.",
                        impact="Full unauthorized access to the application.",
                        remediation="Change default credentials immediately. Force password reset.",
                        confidence=0.8,
                        steps=[
                            f"Navigate to {endpoint.url}",
                            f"Enter username: {username}",
                            f"Enter password: {password}",
                            "Login succeeds with default credentials",
                        ],
                    )

        return None

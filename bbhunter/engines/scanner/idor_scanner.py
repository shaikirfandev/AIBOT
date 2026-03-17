"""
IDOR (Insecure Direct Object Reference) Scanner
=================================================

Tests for broken access control via object reference manipulation.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class IDORScanner(BaseScanner):
    """IDOR vulnerability scanner."""

    CATEGORY = VulnCategory.IDOR

    # Parameters commonly vulnerable to IDOR
    IDOR_PARAMS = [
        "id", "user_id", "uid", "account_id", "account", "profile_id",
        "order_id", "order", "doc_id", "document_id", "file_id",
        "report_id", "invoice_id", "item_id", "product_id", "project_id",
        "message_id", "email_id", "ticket_id", "comment_id",
        "no", "number", "ref", "reference",
    ]

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan for IDOR vulnerabilities."""
        vulnerabilities: list[Vulnerability] = []
        
        for endpoint in endpoints:
            # Check parameters
            for param in endpoint.parameters:
                if param.name.lower() in self.IDOR_PARAMS:
                    vuln = await self._test_idor(endpoint, param.name, target_id, scan_id)
                    if vuln:
                        vulnerabilities.append(vuln)

            # Check URL path for numeric IDs
            path_vuln = await self._test_path_idor(endpoint, target_id, scan_id)
            if path_vuln:
                vulnerabilities.append(path_vuln)

        return vulnerabilities

    async def _test_idor(
        self,
        endpoint: Endpoint,
        param_name: str,
        target_id: str,
        scan_id: str,
    ) -> Vulnerability | None:
        """Test parameter for IDOR by incrementing/decrementing IDs."""
        parsed = urlparse(endpoint.url)
        original_params = parse_qs(parsed.query)
        original_value = original_params.get(param_name, [""])[0]

        if not original_value:
            return None

        # Try to determine if it's a numeric ID
        try:
            original_int = int(original_value)
            test_values = [
                str(original_int + 1),
                str(original_int - 1),
                str(original_int + 100),
                "0",
                "1",
            ]
        except ValueError:
            # Non-numeric, try common substitutions
            test_values = ["1", "0", "admin", "test"]

        # Get baseline response
        baseline = await self._send_request(endpoint.url)
        if baseline is None:
            return None

        for test_val in test_values:
            params = dict(original_params)
            params[param_name] = [test_val]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            resp = await self._send_request(test_url)
            if resp is None:
                continue

            # Check if we got different valid data (not just error pages)
            if (
                resp.status_code == 200
                and len(resp.text) > 100
                and resp.text != baseline.text
                and "error" not in resp.text.lower()[:200]
                and "not found" not in resp.text.lower()[:200]
                and "unauthorized" not in resp.text.lower()[:200]
            ):
                return self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title=f"Potential IDOR via '{param_name}'",
                    severity=Severity.HIGH,
                    url=endpoint.url,
                    parameter=param_name,
                    payload=test_val,
                    description=(
                        f"Changing the '{param_name}' parameter from '{original_value}' "
                        f"to '{test_val}' returned different data with HTTP 200, "
                        f"suggesting broken access control."
                    ),
                    impact=(
                        "Unauthorized access to other users' data. "
                        "Potential PII exposure, data theft, or account manipulation."
                    ),
                    remediation=(
                        "Implement proper authorization checks on every request. "
                        "Verify that the requesting user owns the referenced object. "
                        "Use UUIDs instead of sequential IDs. "
                        "Implement access control lists (ACLs)."
                    ),
                    confidence=0.55,
                    steps=[
                        f"Original request: {endpoint.url}",
                        f"Modified request: {test_url}",
                        "Compare responses for data leakage",
                    ],
                )

        return None

    async def _test_path_idor(
        self, endpoint: Endpoint, target_id: str, scan_id: str
    ) -> Vulnerability | None:
        """Test URL path for IDOR (e.g., /users/123/profile)."""
        parsed = urlparse(endpoint.url)
        path = parsed.path

        # Find numeric segments in path
        segments = path.split("/")
        for i, segment in enumerate(segments):
            if segment.isdigit():
                original_id = int(segment)
                for test_id in [original_id + 1, original_id - 1, 1, 0]:
                    new_segments = list(segments)
                    new_segments[i] = str(test_id)
                    new_path = "/".join(new_segments)
                    test_url = urlunparse(parsed._replace(path=new_path))

                    resp = await self._send_request(test_url)
                    if resp and resp.status_code == 200:
                        baseline = await self._send_request(endpoint.url)
                        if baseline and resp.text != baseline.text and len(resp.text) > 100:
                            return self._create_vulnerability(
                                target_id=target_id,
                                scan_id=scan_id,
                                title=f"Potential Path-based IDOR at {path}",
                                severity=Severity.HIGH,
                                url=endpoint.url,
                                parameter=f"path_segment[{i}]",
                                payload=str(test_id),
                                confidence=0.5,
                            )
        return None

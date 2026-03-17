"""
Base Scanner Module
====================

Abstract base class for all vulnerability scanners.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_action_logger, get_logger
from bbhunter.models import Endpoint, Severity, Vulnerability, VulnCategory

logger = get_logger()
action_logger = get_action_logger()


class BaseScanner(ABC):
    """Abstract base for all vulnerability scanner modules."""

    CATEGORY: VulnCategory = VulnCategory.OTHER

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.scanner.timeout

    @abstractmethod
    async def scan(
        self,
        endpoints: list[Endpoint],
        target_id: str,
        scan_id: str,
    ) -> list[Vulnerability]:
        """Scan endpoints for vulnerabilities."""
        ...

    async def _send_request(
        self,
        url: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
        cookies: dict | None = None,
    ) -> httpx.Response | None:
        """Send an HTTP request with error handling."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                verify=False,
            ) as client:
                action_logger.log_request(method, url)
                resp = await client.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                )
                return resp
        except Exception as e:
            logger.debug(f"Request error ({method} {url}): {e}")
            return None

    def _create_vulnerability(
        self,
        target_id: str,
        scan_id: str,
        title: str,
        severity: Severity,
        url: str = "",
        parameter: str = "",
        payload: str = "",
        evidence: str = "",
        description: str = "",
        impact: str = "",
        remediation: str = "",
        confidence: float = 0.5,
        request: str = "",
        response: str = "",
        steps: list[str] | None = None,
    ) -> Vulnerability:
        """Create a standardized vulnerability finding."""
        return Vulnerability(
            target_id=target_id,
            scan_id=scan_id,
            category=self.CATEGORY,
            severity=severity,
            title=title,
            description=description,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            confidence=confidence,
            request=request,
            response=response,
            steps_to_reproduce=steps or [],
        )

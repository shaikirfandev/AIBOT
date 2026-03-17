"""
Vulnerability Scanner Engine - Core Orchestrator
==================================================

Orchestrates all vulnerability scanning modules:
- OWASP Top 10 testing
- Business logic testing
- API security testing
- Advanced vulnerability detection
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

from bbhunter.config import get_config
from bbhunter.logger import get_action_logger, get_logger
from bbhunter.models import (
    Endpoint,
    ScanResult,
    ScanStatus,
    Vulnerability,
    VulnCategory,
)
from bbhunter.safety import get_safety_gate

from bbhunter.engines.scanner.xss_scanner import XSSScanner
from bbhunter.engines.scanner.sqli_scanner import SQLiScanner
from bbhunter.engines.scanner.ssrf_scanner import SSRFScanner
from bbhunter.engines.scanner.idor_scanner import IDORScanner
from bbhunter.engines.scanner.cors_scanner import CORSScanner
from bbhunter.engines.scanner.open_redirect_scanner import OpenRedirectScanner
from bbhunter.engines.scanner.ssti_scanner import SSTIScanner
from bbhunter.engines.scanner.header_scanner import HeaderScanner
from bbhunter.engines.scanner.jwt_scanner import JWTScanner
from bbhunter.engines.scanner.auth_scanner import AuthScanner

logger = get_logger()
action_logger = get_action_logger()


class VulnerabilityScanner:
    """
    Main vulnerability scanner orchestrator.
    
    Coordinates all vulnerability testing modules and produces
    a comprehensive list of findings.
    """

    def __init__(self):
        self.config = get_config()
        self.safety = get_safety_gate()
        self.scanners = {
            "xss": XSSScanner(),
            "sqli": SQLiScanner(),
            "ssrf": SSRFScanner(),
            "idor": IDORScanner(),
            "cors": CORSScanner(),
            "open_redirect": OpenRedirectScanner(),
            "ssti": SSTIScanner(),
            "headers": HeaderScanner(),
            "jwt": JWTScanner(),
            "auth": AuthScanner(),
        }

    async def run(
        self,
        domain: str,
        endpoints: list[Endpoint],
        categories: list[str] | None = None,
    ) -> ScanResult:
        """
        Execute vulnerability scanning against discovered endpoints.
        
        Args:
            domain: Target domain.
            endpoints: List of endpoints from surface mapping.
            categories: Specific vulnerability categories to test.
        """
        target = self.safety.check(domain, action="vulnerability_scan")
        
        scan = ScanResult(
            target_id=target.id,
            scan_type="vuln_scan",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        action_logger.log_scan_start("vuln_scan", domain)
        logger.info(f"🔫 Starting vulnerability scan: {domain} ({len(endpoints)} endpoints)")

        if categories is None:
            categories = self.config.scanner.categories

        all_vulns: list[Vulnerability] = []

        try:
            # Run selected scanners
            for category in categories:
                scanner = self.scanners.get(category)
                if scanner is None:
                    logger.debug(f"Unknown scanner category: {category}")
                    continue

                logger.info(f"  🔍 Testing: {category.upper()}")
                try:
                    vulns = await scanner.scan(endpoints, target.id, scan.id)
                    all_vulns.extend(vulns)
                    
                    if vulns:
                        logger.warning(
                            f"  ⚠️  {category.upper()}: {len(vulns)} potential finding(s)"
                        )
                except Exception as e:
                    scan.errors.append(f"{category}: {str(e)}")
                    logger.error(f"  ❌ {category} scanner error: {e}")

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.vulnerabilities_found = len(all_vulns)

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.errors.append(str(e))

        scan.metadata["vulnerabilities"] = [v.model_dump() for v in all_vulns]
        action_logger.log_scan_end("vuln_scan", domain, len(all_vulns))
        logger.info(f"✅ Vulnerability scan complete: {len(all_vulns)} findings")

        return scan

    async def scan_single(
        self,
        endpoint: Endpoint,
        category: str,
        target_id: str,
    ) -> list[Vulnerability]:
        """Scan a single endpoint for a specific vulnerability category."""
        scanner = self.scanners.get(category)
        if scanner is None:
            return []
        return await scanner.scan([endpoint], target_id, "manual")

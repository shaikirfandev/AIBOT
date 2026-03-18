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
from datetime import datetime, timezone
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
    Injects PayloadEngine and LearningEngine into scanners that support them.
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
        self._payload_engine: Any = None
        self._learning_engine: Any = None

    def set_payload_engine(self, engine: Any):
        """Inject PayloadEngine for WAF-aware payload generation."""
        self._payload_engine = engine
        # Propagate to scanners that accept it
        for scanner in self.scanners.values():
            if hasattr(scanner, "set_payload_engine"):
                scanner.set_payload_engine(engine)

    def set_learning_engine(self, engine: Any):
        """Inject LearningEngine for effectiveness tracking."""
        self._learning_engine = engine
        # Propagate to scanners that accept it
        for scanner in self.scanners.values():
            if hasattr(scanner, "set_learning_engine"):
                scanner.set_learning_engine(engine)

    async def run(
        self,
        domain: str,
        endpoints: list[Endpoint],
        categories: list[str] | None = None,
        scanners: list[str] | None = None,
    ) -> ScanResult:
        """
        Execute vulnerability scanning against discovered endpoints.
        
        Args:
            domain: Target domain.
            endpoints: List of endpoints from surface mapping.
            categories: Specific vulnerability categories to test.
        """
        target = self.safety.check(domain, action="vulnerability_scan")
        
        # Accept both 'categories' and 'scanners' keyword for compatibility
        if categories is None and scanners is not None:
            categories = scanners

        scan = ScanResult(
            target_id=target.id,
            scan_type="vuln_scan",
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
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
            scan.completed_at = datetime.now(timezone.utc)
            scan.vulnerabilities_found = len(all_vulns)

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.errors.append(str(e))

        scan.metadata["vulnerabilities"] = list(all_vulns)
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

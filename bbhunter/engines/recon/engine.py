"""
Reconnaissance Engine - Core Orchestrator
==========================================

Performs deep reconnaissance on authorized targets:
- Subdomain discovery (passive + active)
- DNS enumeration
- ASN mapping
- Reverse IP lookup
- Wayback archive scraping
- GitHub secret discovery
- Certificate transparency log mining
- Cloud asset discovery
- API endpoint enumeration
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any

from bbhunter.config import get_config
from bbhunter.logger import get_action_logger, get_logger
from bbhunter.models import Asset, AssetType, ScanResult, ScanStatus, Target
from bbhunter.safety import get_safety_gate

from bbhunter.engines.recon.subdomain import SubdomainEnumerator
from bbhunter.engines.recon.dns_enum import DNSEnumerator
from bbhunter.engines.recon.wayback import WaybackScraper
from bbhunter.engines.recon.ct_logs import CTLogEnumerator
from bbhunter.engines.recon.github_recon import GitHubRecon
from bbhunter.engines.recon.cloud_recon import CloudAssetDiscovery
from bbhunter.engines.recon.asn_lookup import ASNLookup
from bbhunter.engines.recon.reverse_ip import ReverseIPLookup

logger = get_logger()
action_logger = get_action_logger()


class ReconEngine:
    """
    Main reconnaissance orchestrator.
    
    Coordinates all recon sub-modules and produces a structured
    asset map of the target ecosystem.
    """

    def __init__(self):
        self.config = get_config()
        self.safety = get_safety_gate()
        self.subdomain_enum = SubdomainEnumerator()
        self.dns_enum = DNSEnumerator()
        self.wayback = WaybackScraper()
        self.ct_logs = CTLogEnumerator()
        self.github_recon = GitHubRecon()
        self.cloud_recon = CloudAssetDiscovery()
        self.asn_lookup = ASNLookup()
        self.reverse_ip = ReverseIPLookup()

    async def run(self, domain: str) -> ScanResult:
        """
        Execute full reconnaissance against an authorized target.
        
        Args:
            domain: Root domain to perform recon on.
            
        Returns:
            ScanResult with all discovered assets.
        """
        # SAFETY CHECK - always first
        target = self.safety.check(domain, action="reconnaissance")
        
        scan = ScanResult(
            target_id=target.id,
            scan_type="recon",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        action_logger.log_scan_start("recon", domain)
        logger.info(f"🔍 Starting reconnaissance on: {domain}")

        all_assets: list[Asset] = []

        try:
            # Phase 1: Passive Reconnaissance (parallel)
            logger.info("📡 Phase 1: Passive Reconnaissance")
            passive_tasks = []

            if self.config.recon.passive.enable_ct_logs:
                passive_tasks.append(self.ct_logs.enumerate(domain, target.id))

            if self.config.recon.passive.enable_wayback:
                passive_tasks.append(self.wayback.scrape(domain, target.id))

            if self.config.recon.passive.enable_github_search:
                passive_tasks.append(self.github_recon.search(domain, target.id))

            passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)
            
            for result in passive_results:
                if isinstance(result, list):
                    all_assets.extend(result)
                elif isinstance(result, Exception):
                    scan.errors.append(str(result))
                    logger.warning(f"Passive recon error: {result}")

            # Phase 2: Active Reconnaissance
            logger.info("🔎 Phase 2: Active Reconnaissance")
            active_tasks = []

            active_tasks.append(self.subdomain_enum.enumerate(domain, target.id))
            active_tasks.append(self.dns_enum.enumerate(domain, target.id))
            active_tasks.append(self.asn_lookup.lookup(domain, target.id))
            active_tasks.append(self.reverse_ip.lookup(domain, target.id))

            active_results = await asyncio.gather(*active_tasks, return_exceptions=True)
            
            for result in active_results:
                if isinstance(result, list):
                    all_assets.extend(result)
                elif isinstance(result, Exception):
                    scan.errors.append(str(result))
                    logger.warning(f"Active recon error: {result}")

            # Phase 3: Cloud Asset Discovery
            logger.info("☁️  Phase 3: Cloud Asset Discovery")
            try:
                cloud_assets = await self.cloud_recon.discover(domain, target.id)
                all_assets.extend(cloud_assets)
            except Exception as e:
                scan.errors.append(str(e))
                logger.warning(f"Cloud recon error: {e}")

            # Deduplicate assets
            all_assets = self._deduplicate_assets(all_assets)

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.assets_found = len(all_assets)

            action_logger.log_scan_end("recon", domain, len(all_assets))
            logger.info(f"✅ Reconnaissance complete: {len(all_assets)} assets discovered")

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.errors.append(str(e))
            logger.error(f"❌ Reconnaissance failed: {e}")

        scan.metadata["assets"] = [a.model_dump() for a in all_assets]
        return scan

    def _deduplicate_assets(self, assets: list[Asset]) -> list[Asset]:
        """Remove duplicate assets based on type + value."""
        seen = set()
        unique = []
        for asset in assets:
            key = (asset.asset_type, asset.value.lower())
            if key not in seen:
                seen.add(key)
                unique.append(asset)
        return unique

    async def quick_recon(self, domain: str) -> list[Asset]:
        """
        Perform a quick lightweight recon (subdomains + DNS only).
        Useful for initial target assessment.
        """
        target = self.safety.check(domain, action="quick_recon")
        logger.info(f"⚡ Quick recon on: {domain}")

        tasks = [
            self.subdomain_enum.enumerate(domain, target.id),
            self.dns_enum.enumerate(domain, target.id),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        assets = []
        for result in results:
            if isinstance(result, list):
                assets.extend(result)
        
        return self._deduplicate_assets(assets)

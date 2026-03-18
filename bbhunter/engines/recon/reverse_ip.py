"""
Reverse IP Lookup Module
=========================

Discovers other domains hosted on the same IP address.
"""

from __future__ import annotations

import asyncio

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class ReverseIPLookup:
    """Discover co-hosted domains via reverse IP lookup."""

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.recon.timeout

    async def lookup(self, domain: str, target_id: str) -> list[Asset]:
        """
        Perform reverse IP lookup to find co-hosted domains.
        """
        logger.info(f"  🔄 Reverse IP lookup: {domain}")
        assets: list[Asset] = []

        try:
            # Resolve domain to IP
            import dns.resolver
            loop = asyncio.get_running_loop()
            resolver = dns.resolver.Resolver()
            answers = await loop.run_in_executor(None, resolver.resolve, domain, "A")

            for rdata in answers:
                ip = str(rdata)
                domains = await self._reverse_lookup(ip)
                
                for found_domain in domains:
                    assets.append(Asset(
                        target_id=target_id,
                        asset_type=AssetType.DOMAIN,
                        value=found_domain,
                        source="reverse_ip",
                        metadata={"shared_ip": ip},
                    ))

        except Exception as e:
            logger.debug(f"Reverse IP error: {e}")

        logger.info(f"  ✅ Reverse IP found {len(assets)} co-hosted domains")
        return assets

    async def _reverse_lookup(self, ip: str) -> list[str]:
        """Query reverse IP databases."""
        domains = set()

        # HackerTarget
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
                )
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.strip().split("\n"):
                        d = line.strip().lower()
                        if d and "." in d:
                            domains.add(d)
        except Exception as exc:
            logger.debug(f"Reverse IP lookup failed: {exc}")

        return list(domains)[:100]  # Limit results

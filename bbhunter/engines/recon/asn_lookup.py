"""
ASN Lookup Module
==================

Maps domains to their Autonomous System Numbers and related infrastructure.
"""

from __future__ import annotations

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class ASNLookup:
    """ASN mapping and IP range discovery."""

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.recon.timeout

    async def lookup(self, domain: str, target_id: str) -> list[Asset]:
        """
        Perform ASN lookup to discover related IP ranges and networks.
        """
        logger.info(f"  🌍 ASN lookup: {domain}")
        assets: list[Asset] = []

        try:
            # Resolve domain to IP first
            import dns.resolver
            import asyncio
            
            loop = asyncio.get_event_loop()
            resolver = dns.resolver.Resolver()
            answers = await loop.run_in_executor(None, resolver.resolve, domain, "A")
            
            for rdata in answers:
                ip = str(rdata)
                
                # Query BGP info
                asn_info = await self._query_asn(ip)
                if asn_info:
                    assets.append(Asset(
                        target_id=target_id,
                        asset_type=AssetType.IP,
                        value=ip,
                        source="asn_lookup",
                        metadata=asn_info,
                    ))

                    # Get related IP ranges for this ASN
                    asn_number = asn_info.get("asn", "")
                    if asn_number:
                        prefixes = await self._get_asn_prefixes(asn_number)
                        for prefix in prefixes:
                            assets.append(Asset(
                                target_id=target_id,
                                asset_type=AssetType.IP,
                                value=prefix,
                                source="asn_prefix",
                                metadata={"asn": asn_number, "type": "prefix"},
                            ))

        except Exception as e:
            logger.debug(f"ASN lookup error: {e}")

        logger.info(f"  ✅ ASN lookup found {len(assets)} network assets")
        return assets

    async def _query_asn(self, ip: str) -> dict | None:
        """Query IP-to-ASN mapping."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Using ip-api.com for ASN info
                resp = await client.get(f"http://ip-api.com/json/{ip}?fields=status,as,org,isp,query")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        as_field = data.get("as", "")
                        asn = as_field.split()[0] if as_field else ""
                        return {
                            "ip": ip,
                            "asn": asn,
                            "as_name": as_field,
                            "org": data.get("org", ""),
                            "isp": data.get("isp", ""),
                        }
        except Exception:
            pass
        return None

    async def _get_asn_prefixes(self, asn: str) -> list[str]:
        """Get IP prefixes announced by an ASN."""
        prefixes = []
        try:
            # Clean ASN number
            asn_num = asn.replace("AS", "").strip()
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"https://api.hackertarget.com/aslookup/?q=AS{asn_num}"
                )
                if resp.status_code == 200:
                    for line in resp.text.strip().split("\n"):
                        line = line.strip()
                        if "/" in line and not line.startswith("No"):
                            prefixes.append(line)
        except Exception:
            pass
        return prefixes[:20]  # Limit results

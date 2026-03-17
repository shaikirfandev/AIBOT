"""
Certificate Transparency Log Enumerator
========================================

Queries CT logs to discover subdomains and certificates.
"""

from __future__ import annotations

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class CTLogEnumerator:
    """Query Certificate Transparency logs for subdomain discovery."""

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.recon.timeout

    async def enumerate(self, domain: str, target_id: str) -> list[Asset]:
        """
        Query multiple CT log sources.
        
        Sources:
        - crt.sh
        - Certspotter
        - Facebook CT
        """
        logger.info(f"  🔐 CT Log enumeration: {domain}")
        assets: list[Asset] = []
        subdomains: set[str] = set()

        # crt.sh
        try:
            crtsh_subs = await self._crtsh(domain)
            subdomains.update(crtsh_subs)
        except Exception as e:
            logger.debug(f"crt.sh CT error: {e}")

        # Certspotter
        try:
            cs_subs = await self._certspotter(domain)
            subdomains.update(cs_subs)
        except Exception as e:
            logger.debug(f"Certspotter error: {e}")

        for sub in subdomains:
            assets.append(Asset(
                target_id=target_id,
                asset_type=AssetType.SUBDOMAIN,
                value=sub,
                source="ct_logs",
            ))

        logger.info(f"  ✅ CT logs found {len(subdomains)} subdomains")
        return assets

    async def _crtsh(self, domain: str) -> set[str]:
        """Query crt.sh for CT log entries."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                for entry in resp.json():
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower()
                        if name and "*" not in name:
                            if name.endswith(f".{domain}") or name == domain:
                                subdomains.add(name)
        
        return subdomains

    async def _certspotter(self, domain: str) -> set[str]:
        """Query Certspotter API."""
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                for cert in resp.json():
                    for name in cert.get("dns_names", []):
                        name = name.strip().lower()
                        if name and "*" not in name:
                            if name.endswith(f".{domain}") or name == domain:
                                subdomains.add(name)
        
        return subdomains

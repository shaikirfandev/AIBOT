"""
Subdomain Enumeration Module
=============================

Discovers subdomains using multiple techniques:
- DNS brute forcing
- Certificate transparency logs
- Search engine scraping
- API integrations (VirusTotal, SecurityTrails, etc.)
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class SubdomainEnumerator:
    """Multi-source subdomain discovery."""

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.recon.timeout
        self.found_subdomains: set[str] = set()

    async def enumerate(self, domain: str, target_id: str) -> list[Asset]:
        """
        Discover subdomains using multiple passive sources.
        
        Sources:
        - crt.sh (Certificate Transparency)
        - HackerTarget
        - ThreatCrowd
        - Alienvault OTX
        - URLScan.io
        """
        logger.info(f"  🌐 Subdomain enumeration: {domain}")
        assets: list[Asset] = []

        tasks = [
            self._crtsh(domain),
            self._hackertarget(domain),
            self._alienvault_otx(domain),
            self._urlscan(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                self.found_subdomains.update(result)
            elif isinstance(result, Exception):
                logger.debug(f"Subdomain source error: {result}")

        # DNS brute force (if enabled)
        if self.config.recon.active.enable_dns_brute:
            brute_results = await self._dns_brute(domain)
            self.found_subdomains.update(brute_results)

        for sub in self.found_subdomains:
            assets.append(Asset(
                target_id=target_id,
                asset_type=AssetType.SUBDOMAIN,
                value=sub,
                source="subdomain_enum",
            ))

        logger.info(f"  ✅ Found {len(assets)} subdomains for {domain}")
        return assets

    async def _crtsh(self, domain: str) -> set[str]:
        """Query crt.sh certificate transparency database."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for line in name.split("\n"):
                            line = line.strip().lower()
                            if line.endswith(f".{domain}") or line == domain:
                                if "*" not in line:
                                    subdomains.add(line)
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")
        
        return subdomains

    async def _hackertarget(self, domain: str) -> set[str]:
        """Query HackerTarget API for subdomains."""
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 200 and "error" not in resp.text.lower():
                    for line in resp.text.strip().split("\n"):
                        parts = line.split(",")
                        if parts:
                            sub = parts[0].strip().lower()
                            if sub.endswith(f".{domain}") or sub == domain:
                                subdomains.add(sub)
        except Exception as e:
            logger.debug(f"HackerTarget error: {e}")
        
        return subdomains

    async def _alienvault_otx(self, domain: str) -> set[str]:
        """Query Alienvault OTX for passive DNS data."""
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get("passive_dns", []):
                        hostname = record.get("hostname", "").lower()
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            subdomains.add(hostname)
        except Exception as e:
            logger.debug(f"AlienVault OTX error: {e}")
        
        return subdomains

    async def _urlscan(self, domain: str) -> set[str]:
        """Query URLScan.io for discovered subdomains."""
        subdomains = set()
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        hostname = page.get("domain", "").lower()
                        if hostname.endswith(f".{domain}") or hostname == domain:
                            subdomains.add(hostname)
        except Exception as e:
            logger.debug(f"URLScan error: {e}")
        
        return subdomains

    async def _dns_brute(self, domain: str) -> set[str]:
        """Brute force subdomains using a wordlist."""
        import dns.resolver
        
        subdomains = set()
        wordlist_path = self.config.recon.active.dns_wordlist

        # Default small wordlist if file not found
        default_words = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
            "blog", "shop", "app", "portal", "vpn", "remote", "webmail",
            "ns1", "ns2", "mx", "smtp", "imap", "pop", "cdn", "static",
            "assets", "media", "img", "images", "docs", "wiki", "git",
            "jenkins", "ci", "cd", "build", "deploy", "monitor", "status",
            "grafana", "kibana", "elastic", "prometheus", "sentry",
            "auth", "sso", "login", "oauth", "id", "accounts",
            "internal", "intranet", "extranet", "private", "corp",
            "staging", "uat", "qa", "sandbox", "demo", "beta",
            "m", "mobile", "ws", "wss", "socket", "graphql",
            "v1", "v2", "v3", "old", "new", "legacy", "backup",
            "db", "database", "redis", "mongo", "mysql", "postgres",
            "s3", "storage", "files", "upload", "downloads",
        ]

        try:
            with open(wordlist_path) as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            words = default_words

        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.config.recon.active.dns_resolvers

        sem = asyncio.Semaphore(self.config.recon.max_concurrent)

        async def _resolve(word: str):
            async with sem:
                fqdn = f"{word}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, resolver.resolve, fqdn, "A")
                    subdomains.add(fqdn)
                except Exception:
                    pass

        await asyncio.gather(*[_resolve(w) for w in words])
        return subdomains

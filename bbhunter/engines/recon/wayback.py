"""
Wayback Machine Scraper
========================

Scrapes the Wayback Machine for historical URLs, endpoints,
and parameters associated with the target domain.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse, parse_qs
from typing import Any

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class WaybackScraper:
    """Scrape Wayback Machine for historical URL data."""

    WAYBACK_CDX_URL = "https://web.archive.org/cdx/search/cdx"

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.recon.timeout

    async def scrape(self, domain: str, target_id: str) -> list[Asset]:
        """
        Query Wayback Machine CDX API to find historical URLs.
        
        Discovers:
        - Old endpoints that may still be active
        - Parameters used in URLs
        - API endpoints
        - Admin panels
        - File paths
        """
        logger.info(f"  📜 Wayback Machine scraping: {domain}")
        assets: list[Asset] = []
        urls_found: set[str] = set()

        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original,statuscode,mimetype",
                "collapse": "urlkey",
                "limit": "5000",
            }

            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.get(self.WAYBACK_CDX_URL, params=params)
                
                if resp.status_code == 200:
                    data = resp.json()
                    # First row is header
                    for row in data[1:]:
                        if len(row) >= 3:
                            url = row[0]
                            status = row[1]
                            mimetype = row[2]

                            # Filter out static resources
                            if self._is_interesting_url(url):
                                urls_found.add(url)

        except Exception as e:
            logger.debug(f"Wayback error: {e}")

        # Also query the Common Crawl index
        try:
            cc_urls = await self._common_crawl(domain)
            urls_found.update(cc_urls)
        except Exception as e:
            logger.debug(f"Common Crawl error: {e}")

        for url in urls_found:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            # Record the URL
            assets.append(Asset(
                target_id=target_id,
                asset_type=AssetType.URL,
                value=url,
                source="wayback",
                metadata={
                    "hostname": hostname,
                    "path": parsed.path,
                    "params": dict(parse_qs(parsed.query)),
                },
            ))

            # Extract subdomain if new
            if hostname and hostname != domain and hostname.endswith(f".{domain}"):
                assets.append(Asset(
                    target_id=target_id,
                    asset_type=AssetType.SUBDOMAIN,
                    value=hostname,
                    source="wayback",
                ))

        logger.info(f"  ✅ Wayback found {len(urls_found)} interesting URLs")
        return assets

    async def _common_crawl(self, domain: str) -> set[str]:
        """Query Common Crawl index for additional historical URLs."""
        urls = set()
        cc_url = f"https://index.commoncrawl.org/CC-MAIN-2025-06-index?url=*.{domain}&output=json&limit=1000"
        
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(cc_url)
                if resp.status_code == 200:
                    for line in resp.text.strip().split("\n"):
                        try:
                            import json
                            entry = json.loads(line)
                            url = entry.get("url", "")
                            if self._is_interesting_url(url):
                                urls.add(url)
                        except Exception as exc:
                            logger.debug(f"Failed to parse wayback entry: {exc}")
        except Exception as exc:
            logger.debug(f"Wayback URL fetch failed: {exc}")
        
        return urls

    def _is_interesting_url(self, url: str) -> bool:
        """Filter out static resources and keep interesting endpoints."""
        # Skip static resources
        static_extensions = {
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
            ".svg", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4",
            ".avi", ".mov", ".pdf", ".zip", ".tar", ".gz",
        }
        
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        for ext in static_extensions:
            if path_lower.endswith(ext):
                return False

        # Interesting patterns
        interesting_patterns = [
            "/api/", "/admin", "/login", "/auth", "/graphql",
            "/upload", "/file", "/download", "/export", "/import",
            "/config", "/settings", "/debug", "/internal",
            "/v1/", "/v2/", "/v3/", "/rest/", "/ws/",
            ".php", ".asp", ".aspx", ".jsp", ".json", ".xml",
            "token", "key", "secret", "password", "callback",
            "redirect", "url=", "next=", "return=",
        ]
        
        url_lower = url.lower()
        for pattern in interesting_patterns:
            if pattern in url_lower:
                return True

        # Keep URLs with query parameters
        if parsed.query:
            return True

        return False

"""
Surface Mapping Engine - Core Orchestrator
============================================

Maps the complete attack surface of a target:
- Web crawler for endpoint discovery
- JavaScript analysis for hidden APIs
- Parameter discovery
- Technology fingerprinting
- WAF/CDN detection
- GraphQL / Swagger / OpenAPI detection
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from bbhunter.config import get_config
from bbhunter.logger import get_action_logger, get_logger
from bbhunter.models import (
    Asset,
    AssetType,
    Endpoint,
    Parameter,
    ScanResult,
    ScanStatus,
    Target,
)
from bbhunter.safety import get_safety_gate

logger = get_logger()
action_logger = get_action_logger()


class SurfaceMappingEngine:
    """
    Attack surface mapping engine.
    
    Crawls, analyzes, and maps all endpoints, parameters,
    and technologies of the target.
    """

    # Technology fingerprints (response header / body patterns)
    TECH_FINGERPRINTS = {
        "nginx": {"headers": ["server:nginx"]},
        "apache": {"headers": ["server:apache"]},
        "cloudflare": {"headers": ["server:cloudflare", "cf-ray"]},
        "akamai": {"headers": ["x-akamai"]},
        "aws_alb": {"headers": ["server:awselb"]},
        "express": {"headers": ["x-powered-by:express"]},
        "asp.net": {"headers": ["x-powered-by:asp.net", "x-aspnet-version"]},
        "php": {"headers": ["x-powered-by:php"]},
        "django": {"body": ["csrfmiddlewaretoken"]},
        "rails": {"headers": ["x-powered-by:phusion", "x-runtime"]},
        "wordpress": {"body": ["wp-content", "wp-json"]},
        "react": {"body": ["_reactRootContainer", "__NEXT_DATA__"]},
        "angular": {"body": ["ng-version", "ng-app"]},
        "vue": {"body": ["__vue__", "data-v-"]},
        "graphql": {"body": ["__schema", "graphql"]},
    }

    # Common WAF signatures
    WAF_SIGNATURES = {
        "cloudflare": ["cf-ray", "cloudflare"],
        "akamai": ["akamai", "x-akamai"],
        "aws_waf": ["awswaf", "x-amzn-waf"],
        "imperva": ["incap_ses", "visid_incap"],
        "sucuri": ["sucuri", "x-sucuri"],
        "f5_bigip": ["bigip", "f5"],
        "modsecurity": ["mod_security", "modsecurity"],
    }

    def __init__(self):
        self.config = get_config()
        self.safety = get_safety_gate()
        self.visited_urls: set[str] = set()
        self.discovered_endpoints: list[Endpoint] = []
        self.technologies: set[str] = set()
        self.waf_detected: str | None = None

    async def run(self, domain: str, seed_urls: list[str] | None = None) -> ScanResult:
        """
        Execute full surface mapping against a target.
        
        Args:
            domain: Target domain.
            seed_urls: Optional list of starting URLs (from recon).
        """
        target = self.safety.check(domain, action="surface_mapping")
        
        scan = ScanResult(
            target_id=target.id,
            scan_type="surface_map",
            status=ScanStatus.RUNNING,
            started_at=datetime.utcnow(),
        )
        action_logger.log_scan_start("surface_map", domain)
        logger.info(f"🗺️  Starting surface mapping: {domain}")

        if not seed_urls:
            seed_urls = [
                f"https://{domain}",
                f"https://{domain}/robots.txt",
                f"https://{domain}/sitemap.xml",
            ]

        try:
            # Phase 1: Web Crawling
            logger.info("🕷️  Phase 1: Web Crawling")
            await self._crawl(seed_urls, target, depth=0)

            # Phase 2: JavaScript Analysis
            if self.config.surface_mapping.js_analysis:
                logger.info("📜 Phase 2: JavaScript Analysis")
                await self._analyze_javascript(target)

            # Phase 3: API Discovery
            logger.info("🔌 Phase 3: API Discovery")
            await self._discover_apis(domain, target)

            # Phase 4: Technology Fingerprinting
            if self.config.surface_mapping.technology_fingerprint:
                logger.info("🔧 Phase 4: Technology Fingerprinting")
                await self._fingerprint_technology(domain)

            # Phase 5: WAF Detection
            if self.config.surface_mapping.waf_detection:
                logger.info("🛡️  Phase 5: WAF Detection")
                await self._detect_waf(domain)

            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.endpoints_found = len(self.discovered_endpoints)

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.errors.append(str(e))
            logger.error(f"❌ Surface mapping failed: {e}")

        scan.metadata["endpoints"] = [e.model_dump() for e in self.discovered_endpoints]
        scan.metadata["technologies"] = list(self.technologies)
        scan.metadata["waf"] = self.waf_detected

        action_logger.log_scan_end("surface_map", domain, len(self.discovered_endpoints))
        logger.info(
            f"✅ Surface mapping complete: {len(self.discovered_endpoints)} endpoints, "
            f"{len(self.technologies)} technologies detected"
        )
        return scan

    async def _crawl(self, urls: list[str], target: Target, depth: int):
        """Recursive web crawler with depth control."""
        if depth >= self.config.surface_mapping.crawl_depth:
            return
        if len(self.visited_urls) >= self.config.surface_mapping.max_urls:
            return

        sem = asyncio.Semaphore(10)

        async def _fetch(url: str):
            async with sem:
                if url in self.visited_urls:
                    return
                if len(self.visited_urls) >= self.config.surface_mapping.max_urls:
                    return
                    
                # Scope check
                if not self.safety.is_url_in_scope(url, target):
                    return

                self.visited_urls.add(url)
                action_logger.log_request("GET", url)

                try:
                    async with httpx.AsyncClient(
                        timeout=self.config.surface_mapping.timeout,
                        follow_redirects=True,
                        verify=False,
                    ) as client:
                        resp = await client.get(url)
                        
                        # Build endpoint
                        parsed = urlparse(url)
                        endpoint = Endpoint(
                            target_id=target.id,
                            url=url,
                            method="GET",
                            status_code=resp.status_code,
                            content_type=resp.headers.get("content-type", ""),
                            headers=dict(resp.headers),
                        )

                        # Extract parameters from URL
                        if parsed.query:
                            from urllib.parse import parse_qs
                            params = parse_qs(parsed.query)
                            for name, values in params.items():
                                endpoint.parameters.append(Parameter(
                                    name=name,
                                    location="query",
                                    sample_value=values[0] if values else "",
                                ))

                        self.discovered_endpoints.append(endpoint)

                        # Parse HTML for more links
                        if "text/html" in resp.headers.get("content-type", ""):
                            new_urls = self._extract_urls(resp.text, url)
                            # Recurse
                            if depth < self.config.surface_mapping.crawl_depth - 1:
                                await self._crawl(
                                    list(new_urls - self.visited_urls),
                                    target,
                                    depth + 1,
                                )

                except Exception as e:
                    logger.debug(f"Crawl error for {url}: {e}")

        await asyncio.gather(*[_fetch(u) for u in urls])

    def _extract_urls(self, html: str, base_url: str) -> set[str]:
        """Extract URLs from HTML content."""
        urls = set()
        try:
            soup = BeautifulSoup(html, "lxml")

            # <a href>
            for tag in soup.find_all("a", href=True):
                urls.add(urljoin(base_url, tag["href"]))

            # <form action>
            for tag in soup.find_all("form", action=True):
                urls.add(urljoin(base_url, tag["action"]))

            # <script src>
            for tag in soup.find_all("script", src=True):
                urls.add(urljoin(base_url, tag["src"]))

            # <link href>
            for tag in soup.find_all("link", href=True):
                urls.add(urljoin(base_url, tag["href"]))

            # <iframe src>
            for tag in soup.find_all("iframe", src=True):
                urls.add(urljoin(base_url, tag["src"]))

        except Exception:
            pass

        # Also extract from inline JS
        js_urls = re.findall(r'''['"](https?://[^'"]+)['"]''', html)
        for u in js_urls:
            urls.add(u)

        return urls

    async def _analyze_javascript(self, target: Target):
        """Analyze JavaScript files for hidden endpoints and secrets."""
        js_endpoints = set()

        # Patterns to find in JavaScript
        patterns = [
            r'''['"](/api/[^'"]+)['"]''',
            r'''['"](/v[12]/[^'"]+)['"]''',
            r'''['"](/graphql[^'"]*?)['"]''',
            r'''fetch\(['"](/?[^'"]+)['"]''',
            r'''axios\.\w+\(['"](/?[^'"]+)['"]''',
            r'''\.get\(['"](/?[^'"]+)['"]''',
            r'''\.post\(['"](/?[^'"]+)['"]''',
            r'''\.put\(['"](/?[^'"]+)['"]''',
            r'''\.delete\(['"](/?[^'"]+)['"]''',
            r'''url:\s*['"](/?[^'"]+)['"]''',
            r'''endpoint:\s*['"](/?[^'"]+)['"]''',
            r'''path:\s*['"](/?[^'"]+)['"]''',
        ]

        # Find all JS files from crawled endpoints
        js_urls = [
            ep.url for ep in self.discovered_endpoints
            if ep.url.endswith(".js") or "javascript" in ep.content_type
        ]

        for js_url in js_urls[:50]:  # Limit JS analysis
            try:
                async with httpx.AsyncClient(timeout=15, verify=False) as client:
                    resp = await client.get(js_url)
                    if resp.status_code == 200:
                        content = resp.text
                        for pattern in patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                if match.startswith("/"):
                                    parsed = urlparse(js_url)
                                    full_url = f"{parsed.scheme}://{parsed.netloc}{match}"
                                    js_endpoints.add(full_url)
                                elif match.startswith("http"):
                                    js_endpoints.add(match)
            except Exception:
                pass

        # Add discovered JS endpoints
        for url in js_endpoints:
            if url not in self.visited_urls:
                self.discovered_endpoints.append(Endpoint(
                    target_id=target.id,
                    url=url,
                    method="GET",
                    metadata={"source": "js_analysis"},
                ))

        logger.info(f"  📜 JS analysis found {len(js_endpoints)} hidden endpoints")

    async def _discover_apis(self, domain: str, target: Target):
        """Discover API documentation and endpoints."""
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/rest/v1", "/rest/v2",
            "/graphql", "/graphiql", "/playground",
            "/swagger.json", "/swagger/v1/swagger.json",
            "/api-docs", "/api/docs", "/api/swagger",
            "/openapi.json", "/openapi.yaml",
            "/v1/docs", "/v2/docs",
            "/.well-known/openid-configuration",
            "/healthz", "/health", "/status",
            "/metrics", "/debug", "/info",
            "/actuator", "/actuator/health",
            "/wp-json/wp/v2/users",
        ]

        base_urls = [f"https://{domain}", f"http://{domain}"]

        for base in base_urls:
            for path in api_paths:
                url = f"{base}{path}"
                if url in self.visited_urls:
                    continue
                
                try:
                    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
                        resp = await client.get(url)
                        if resp.status_code in (200, 301, 302, 401, 403):
                            self.discovered_endpoints.append(Endpoint(
                                target_id=target.id,
                                url=url,
                                method="GET",
                                status_code=resp.status_code,
                                content_type=resp.headers.get("content-type", ""),
                                metadata={"source": "api_discovery"},
                            ))
                            self.visited_urls.add(url)
                except Exception:
                    pass

    async def _fingerprint_technology(self, domain: str):
        """Identify technologies used by the target."""
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                resp = await client.get(f"https://{domain}")
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body_lower = resp.text.lower()

                for tech, signatures in self.TECH_FINGERPRINTS.items():
                    # Check headers
                    for header_sig in signatures.get("headers", []):
                        parts = header_sig.split(":", 1)
                        if len(parts) == 2:
                            header_name, header_val = parts
                            if header_name in headers_lower and header_val in headers_lower[header_name]:
                                self.technologies.add(tech)
                        elif len(parts) == 1:
                            if parts[0] in headers_lower:
                                self.technologies.add(tech)

                    # Check body
                    for body_sig in signatures.get("body", []):
                        if body_sig in body_lower:
                            self.technologies.add(tech)

        except Exception as e:
            logger.debug(f"Fingerprint error: {e}")

    async def _detect_waf(self, domain: str):
        """Detect Web Application Firewall."""
        try:
            # Send a request with a suspicious payload to trigger WAF
            test_url = f"https://{domain}/?test=<script>alert(1)</script>"
            async with httpx.AsyncClient(timeout=15, verify=False) as client:
                resp = await client.get(test_url)
                headers_str = str(resp.headers).lower()
                body_lower = resp.text.lower()

                for waf_name, signatures in self.WAF_SIGNATURES.items():
                    for sig in signatures:
                        if sig in headers_str or sig in body_lower:
                            self.waf_detected = waf_name
                            logger.info(f"  🛡️  WAF detected: {waf_name}")
                            return

                # Check for generic WAF indicators
                if resp.status_code in (403, 406, 429, 503):
                    if any(w in body_lower for w in ["blocked", "forbidden", "firewall", "security"]):
                        self.waf_detected = "unknown_waf"
                        logger.info("  🛡️  WAF detected: Unknown WAF")

        except Exception as e:
            logger.debug(f"WAF detection error: {e}")

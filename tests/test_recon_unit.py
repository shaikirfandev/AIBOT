"""Unit tests for recon modules in bbhunter/engines/recon/."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from bbhunter.models import Asset, AssetType


# ── Helpers ──────────────────────────────────────────────────────────────

def _mock_httpx_response(
    status_code: int = 200,
    text: str = "",
    json_data: list | dict | None = None,
) -> httpx.Response:
    """Build a fake httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text if text else (json.dumps(json_data) if json_data else "")
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = json.JSONDecodeError("", "", 0)
    resp.headers = httpx.Headers({})
    return resp


# ── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _load_config(config_file: Path):
    from bbhunter.config import load_config
    import bbhunter.config as mod
    mod._config = load_config(config_file)


# ============================================================================
#  SubdomainEnumerator
# ============================================================================

class TestSubdomainEnumerator:
    """Tests for SubdomainEnumerator."""

    def test_instantiation(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()
        assert hasattr(se, "found_subdomains")
        assert isinstance(se.found_subdomains, set)

    def test_enumerate_is_async(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        assert inspect.iscoroutinefunction(SubdomainEnumerator.enumerate)

    async def test_crtsh_parses_results(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()

        mock_data = [
            {"name_value": "sub1.example.com"},
            {"name_value": "sub2.example.com\nsub3.example.com"},
            {"name_value": "*.example.com"},  # wildcard – should be skipped
        ]
        mock_resp = _mock_httpx_response(json_data=mock_data)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await se._crtsh("example.com")

        assert "sub1.example.com" in subs
        assert "sub2.example.com" in subs
        assert "sub3.example.com" in subs
        # Wildcard entries should NOT be included
        assert not any("*" in s for s in subs)

    async def test_crtsh_handles_error(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await se._crtsh("example.com")

        assert subs == set()

    async def test_hackertarget_parses_results(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()

        text = "api.example.com,1.2.3.4\nwww.example.com,5.6.7.8"
        mock_resp = _mock_httpx_response(text=text)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await se._hackertarget("example.com")

        assert "api.example.com" in subs
        assert "www.example.com" in subs

    async def test_hackertarget_handles_error_response(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()

        mock_resp = _mock_httpx_response(text="error check")
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await se._hackertarget("example.com")

        assert len(subs) == 0

    async def test_alienvault_otx_parses_results(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()

        mock_data = {
            "passive_dns": [
                {"hostname": "api.example.com"},
                {"hostname": "mail.example.com"},
                {"hostname": "other.notexample.com"},
            ]
        }
        mock_resp = _mock_httpx_response(json_data=mock_data)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await se._alienvault_otx("example.com")

        assert "api.example.com" in subs
        assert "mail.example.com" in subs
        assert "other.notexample.com" not in subs

    async def test_urlscan_parses_results(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()

        mock_data = {
            "results": [
                {"page": {"domain": "cdn.example.com"}},
                {"page": {"domain": "example.com"}},
            ]
        }
        mock_resp = _mock_httpx_response(json_data=mock_data)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await se._urlscan("example.com")

        assert "cdn.example.com" in subs
        assert "example.com" in subs

    async def test_enumerate_gathers_all_sources(self):
        from bbhunter.engines.recon.subdomain import SubdomainEnumerator
        se = SubdomainEnumerator()

        se._crtsh = AsyncMock(return_value={"sub1.example.com"})
        se._hackertarget = AsyncMock(return_value={"sub2.example.com"})
        se._alienvault_otx = AsyncMock(return_value={"sub3.example.com"})
        se._urlscan = AsyncMock(return_value=set())

        # Disable DNS brute
        se.config.recon.active.enable_dns_brute = False

        assets = await se.enumerate("example.com", "target-1")
        assert len(assets) == 3
        values = {a.value for a in assets}
        assert "sub1.example.com" in values
        assert "sub2.example.com" in values
        assert all(a.asset_type == AssetType.SUBDOMAIN for a in assets)


# ============================================================================
#  CTLogEnumerator
# ============================================================================

class TestCTLogEnumerator:
    """Tests for CTLogEnumerator."""

    def test_instantiation(self):
        from bbhunter.engines.recon.ct_logs import CTLogEnumerator
        ct = CTLogEnumerator()
        assert hasattr(ct, "timeout")

    def test_enumerate_is_async(self):
        from bbhunter.engines.recon.ct_logs import CTLogEnumerator
        assert inspect.iscoroutinefunction(CTLogEnumerator.enumerate)

    async def test_crtsh_parses(self):
        from bbhunter.engines.recon.ct_logs import CTLogEnumerator
        ct = CTLogEnumerator()

        mock_data = [
            {"name_value": "api.example.com"},
            {"name_value": "*.example.com"},
        ]
        mock_resp = _mock_httpx_response(json_data=mock_data)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await ct._crtsh("example.com")

        assert "api.example.com" in subs
        assert not any("*" in s for s in subs)

    async def test_certspotter_parses(self):
        from bbhunter.engines.recon.ct_logs import CTLogEnumerator
        ct = CTLogEnumerator()

        mock_data = [
            {"dns_names": ["cert.example.com", "*.example.com"]},
            {"dns_names": ["api.example.com"]},
        ]
        mock_resp = _mock_httpx_response(json_data=mock_data)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            subs = await ct._certspotter("example.com")

        assert "cert.example.com" in subs
        assert "api.example.com" in subs

    async def test_enumerate_combines_sources(self):
        from bbhunter.engines.recon.ct_logs import CTLogEnumerator
        ct = CTLogEnumerator()

        ct._crtsh = AsyncMock(return_value={"ct1.example.com"})
        ct._certspotter = AsyncMock(return_value={"ct2.example.com"})

        assets = await ct.enumerate("example.com", "target-1")
        values = {a.value for a in assets}
        assert "ct1.example.com" in values
        assert "ct2.example.com" in values

    async def test_enumerate_handles_source_error(self):
        from bbhunter.engines.recon.ct_logs import CTLogEnumerator
        ct = CTLogEnumerator()

        ct._crtsh = AsyncMock(side_effect=Exception("crt.sh down"))
        ct._certspotter = AsyncMock(return_value={"ok.example.com"})

        assets = await ct.enumerate("example.com", "target-1")
        assert len(assets) == 1


# ============================================================================
#  WaybackScraper
# ============================================================================

class TestWaybackScraper:
    """Tests for WaybackScraper."""

    def test_instantiation(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        ws = WaybackScraper()
        assert ws.WAYBACK_CDX_URL.startswith("https://web.archive.org")

    def test_scrape_is_async(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        assert inspect.iscoroutinefunction(WaybackScraper.scrape)

    def test_is_interesting_url_filters_static(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        ws = WaybackScraper()
        assert ws._is_interesting_url("https://example.com/style.css") is False
        assert ws._is_interesting_url("https://example.com/pic.png") is False
        assert ws._is_interesting_url("https://example.com/font.woff2") is False

    def test_is_interesting_url_keeps_api(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        ws = WaybackScraper()
        assert ws._is_interesting_url("https://example.com/api/v1/users") is True
        assert ws._is_interesting_url("https://example.com/admin/login") is True

    def test_is_interesting_url_keeps_params(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        ws = WaybackScraper()
        assert ws._is_interesting_url("https://example.com/page?id=1") is True

    async def test_scrape_returns_assets(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        ws = WaybackScraper()

        cdx_data = [
            ["original", "statuscode", "mimetype"],
            ["https://example.com/api/v1/data?token=abc", "200", "text/html"],
            ["https://sub.example.com/admin", "200", "text/html"],
        ]
        mock_resp = _mock_httpx_response(json_data=cdx_data)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assets = await ws.scrape("example.com", "target-1")

        url_assets = [a for a in assets if a.asset_type == AssetType.URL]
        assert len(url_assets) >= 1

    async def test_scrape_handles_error(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        ws = WaybackScraper()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assets = await ws.scrape("example.com", "target-1")

        assert assets == []

    async def test_common_crawl_parses(self):
        from bbhunter.engines.recon.wayback import WaybackScraper
        ws = WaybackScraper()

        lines = (
            json.dumps({"url": "https://example.com/api/v1/test"}) + "\n"
            + json.dumps({"url": "https://example.com/logo.png"})
        )
        mock_resp = _mock_httpx_response(text=lines)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            urls = await ws._common_crawl("example.com")

        assert "https://example.com/api/v1/test" in urls
        # logo.png is static → filtered
        assert "https://example.com/logo.png" not in urls


# ============================================================================
#  GitHubRecon
# ============================================================================

class TestGitHubRecon:
    """Tests for GitHubRecon."""

    def test_instantiation(self):
        from bbhunter.engines.recon.github_recon import GitHubRecon
        gh = GitHubRecon()
        assert gh.GITHUB_API == "https://api.github.com"

    def test_search_is_async(self):
        from bbhunter.engines.recon.github_recon import GitHubRecon
        assert inspect.iscoroutinefunction(GitHubRecon.search)

    def test_secret_patterns_valid(self):
        import re
        from bbhunter.engines.recon.github_recon import GitHubRecon
        gh = GitHubRecon()
        for pattern in gh.SECRET_PATTERNS:
            re.compile(pattern)

    async def test_search_returns_assets(self):
        from bbhunter.engines.recon.github_recon import GitHubRecon
        gh = GitHubRecon()

        mock_data = {
            "items": [
                {
                    "repository": {"full_name": "org/repo1"},
                    "path": "config.yml",
                    "html_url": "https://github.com/org/repo1/blob/main/config.yml",
                }
            ]
        }
        mock_resp = _mock_httpx_response(json_data=mock_data)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assets = await gh.search("example.com", "target-1")

        assert len(assets) >= 1
        assert any(a.asset_type == AssetType.REPOSITORY for a in assets)

    async def test_search_handles_rate_limit(self):
        from bbhunter.engines.recon.github_recon import GitHubRecon
        gh = GitHubRecon()

        mock_resp = _mock_httpx_response(status_code=403, text="rate limit exceeded")
        mock_resp.json.return_value = {"items": []}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            assets = await gh.search("example.com", "target-1")

        assert assets == []


# ============================================================================
#  DNSEnumerator
# ============================================================================

class TestDNSEnumerator:
    """Tests for DNSEnumerator."""

    def test_instantiation(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        with patch("dns.resolver.Resolver"):
            de = DNSEnumerator()
            assert "A" in de.RECORD_TYPES
            assert "MX" in de.RECORD_TYPES

    def test_enumerate_is_async(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        assert inspect.iscoroutinefunction(DNSEnumerator.enumerate)

    def test_resolve_handles_error(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
            mock_resolver_cls.return_value = mock_resolver
            de = DNSEnumerator()
            de.resolver = mock_resolver
            result = de._resolve("example.com", "A")
            assert result == []

    def test_resolve_returns_records(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            mock_rdata1 = MagicMock()
            mock_rdata1.__str__ = lambda self: "1.2.3.4"
            mock_resolver = MagicMock()
            mock_resolver.resolve.return_value = [mock_rdata1]
            mock_resolver_cls.return_value = mock_resolver

            de = DNSEnumerator()
            de.resolver = mock_resolver
            result = de._resolve("example.com", "A")
            assert "1.2.3.4" in result

    def test_analyze_txt_spf(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        with patch("dns.resolver.Resolver"):
            de = DNSEnumerator()
            assets: list[Asset] = []
            de._analyze_txt_record("v=spf1 include:_spf.google.com ~all", "example.com", "t1", assets)
            assert len(assets) >= 1
            assert any("spf" in a.metadata.get("type", "") for a in assets)

    def test_analyze_txt_dmarc(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        with patch("dns.resolver.Resolver"):
            de = DNSEnumerator()
            assets: list[Asset] = []
            de._analyze_txt_record("v=DMARC1; p=reject", "example.com", "t1", assets)
            assert len(assets) >= 1

    def test_analyze_txt_verification(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        with patch("dns.resolver.Resolver"):
            de = DNSEnumerator()
            assets: list[Asset] = []
            de._analyze_txt_record("google-site-verification=abc123", "example.com", "t1", assets)
            assert len(assets) >= 1

    def test_analyze_txt_no_match(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator
        with patch("dns.resolver.Resolver"):
            de = DNSEnumerator()
            assets: list[Asset] = []
            de._analyze_txt_record("just a random txt record", "example.com", "t1", assets)
            assert len(assets) == 0

    async def test_enumerate_resolves_records(self):
        from bbhunter.engines.recon.dns_enum import DNSEnumerator

        with patch("dns.resolver.Resolver"):
            de = DNSEnumerator()

        de._resolve = MagicMock(return_value=["1.2.3.4"])
        de._zone_transfer = MagicMock(return_value=[])

        assets = await de.enumerate("example.com", "target-1")
        # Should have some assets from the A record resolution
        assert len(assets) >= 1


# ============================================================================
#  CloudAssetDiscovery
# ============================================================================

class TestCloudAssetDiscovery:
    """Tests for CloudAssetDiscovery."""

    def test_instantiation(self):
        from bbhunter.engines.recon.cloud_recon import CloudAssetDiscovery
        cad = CloudAssetDiscovery()
        assert len(cad.S3_PATTERNS) > 0
        assert len(cad.AZURE_PATTERNS) > 0

    def test_discover_is_async(self):
        from bbhunter.engines.recon.cloud_recon import CloudAssetDiscovery
        assert inspect.iscoroutinefunction(CloudAssetDiscovery.discover)

    async def test_discover_runs_and_returns_list(self):
        from bbhunter.engines.recon.cloud_recon import CloudAssetDiscovery
        cad = CloudAssetDiscovery()

        cad._check_s3_buckets = AsyncMock(return_value=[])
        cad._check_azure_blobs = AsyncMock(return_value=[])
        cad._check_gcp_buckets = AsyncMock(return_value=[])

        assets = await cad.discover("example.com", "target-1")
        assert assets == []
        cad._check_s3_buckets.assert_called_once()

    async def test_discover_handles_partial_failure(self):
        from bbhunter.engines.recon.cloud_recon import CloudAssetDiscovery
        cad = CloudAssetDiscovery()

        cad._check_s3_buckets = AsyncMock(
            return_value=[
                Asset(target_id="t1", asset_type=AssetType.S3_BUCKET, value="example-com", source="cloud_s3")
            ]
        )
        cad._check_azure_blobs = AsyncMock(side_effect=Exception("azure down"))
        cad._check_gcp_buckets = AsyncMock(return_value=[])

        assets = await cad.discover("example.com", "target-1")
        assert len(assets) == 1


# ============================================================================
#  ASNLookup
# ============================================================================

class TestASNLookup:
    """Tests for ASNLookup."""

    def test_instantiation(self):
        from bbhunter.engines.recon.asn_lookup import ASNLookup
        asn = ASNLookup()
        assert hasattr(asn, "timeout")

    def test_lookup_is_async(self):
        from bbhunter.engines.recon.asn_lookup import ASNLookup
        assert inspect.iscoroutinefunction(ASNLookup.lookup)

    async def test_query_asn_parses(self):
        from bbhunter.engines.recon.asn_lookup import ASNLookup
        asn = ASNLookup()

        mock_data = {
            "status": "success",
            "as": "AS15169 Google LLC",
            "org": "Google LLC",
            "isp": "Google",
            "query": "8.8.8.8",
        }
        mock_resp = _mock_httpx_response(json_data=mock_data)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await asn._query_asn("8.8.8.8")

        assert result is not None
        assert result["asn"] == "AS15169"

    async def test_query_asn_handles_failure(self):
        from bbhunter.engines.recon.asn_lookup import ASNLookup
        asn = ASNLookup()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            result = await asn._query_asn("8.8.8.8")

        assert result is None


# ============================================================================
#  ReverseIPLookup
# ============================================================================

class TestReverseIPLookup:
    """Tests for ReverseIPLookup."""

    def test_instantiation(self):
        from bbhunter.engines.recon.reverse_ip import ReverseIPLookup
        rip = ReverseIPLookup()
        assert hasattr(rip, "timeout")

    def test_lookup_is_async(self):
        from bbhunter.engines.recon.reverse_ip import ReverseIPLookup
        assert inspect.iscoroutinefunction(ReverseIPLookup.lookup)

    async def test_reverse_lookup_parses(self):
        from bbhunter.engines.recon.reverse_ip import ReverseIPLookup
        rip = ReverseIPLookup()

        text = "domain1.com\ndomain2.com\ndomain3.com"
        mock_resp = _mock_httpx_response(text=text)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            domains = await rip._reverse_lookup("1.2.3.4")

        assert "domain1.com" in domains
        assert "domain2.com" in domains

    async def test_reverse_lookup_handles_error_text(self):
        from bbhunter.engines.recon.reverse_ip import ReverseIPLookup
        rip = ReverseIPLookup()

        text = "error invalid query"
        mock_resp = _mock_httpx_response(text=text)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            domains = await rip._reverse_lookup("1.2.3.4")

        assert len(domains) == 0

    async def test_reverse_lookup_limits_results(self):
        from bbhunter.engines.recon.reverse_ip import ReverseIPLookup
        rip = ReverseIPLookup()

        # 200 domains, should be limited to 100
        text = "\n".join(f"domain{i}.com" for i in range(200))
        mock_resp = _mock_httpx_response(text=text)
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            domains = await rip._reverse_lookup("1.2.3.4")

        assert len(domains) <= 100

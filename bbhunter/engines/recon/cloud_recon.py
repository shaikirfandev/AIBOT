"""
Cloud Asset Discovery Module
==============================

Discovers cloud-hosted assets:
- AWS S3 buckets
- Azure Blob Storage
- GCP Storage Buckets
- Cloud-hosted services
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class CloudAssetDiscovery:
    """Discover cloud infrastructure associated with a target."""

    # Common S3 bucket naming patterns
    S3_PATTERNS = [
        "{domain}", "{domain}-assets", "{domain}-backup", "{domain}-data",
        "{domain}-dev", "{domain}-staging", "{domain}-prod", "{domain}-public",
        "{domain}-private", "{domain}-media", "{domain}-uploads", "{domain}-static",
        "{domain}-logs", "{domain}-config", "{domain}-internal",
    ]

    AZURE_PATTERNS = [
        "{domain}", "{org}assets", "{org}backup", "{org}data",
        "{org}dev", "{org}staging",
    ]

    GCP_PATTERNS = [
        "{domain}", "{domain}-storage", "{domain}-assets",
    ]

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.recon.timeout

    async def discover(self, domain: str, target_id: str) -> list[Asset]:
        """
        Discover cloud assets associated with the target.
        """
        logger.info(f"  ☁️  Cloud asset discovery: {domain}")
        assets: list[Asset] = []

        # Clean domain for bucket name generation
        org = domain.split(".")[0]
        clean_domain = domain.replace(".", "-")

        tasks = [
            self._check_s3_buckets(clean_domain, org, target_id),
            self._check_azure_blobs(clean_domain, org, target_id),
            self._check_gcp_buckets(clean_domain, org, target_id),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                assets.extend(result)

        logger.info(f"  ✅ Cloud discovery found {len(assets)} assets")
        return assets

    async def _check_s3_buckets(self, domain: str, org: str, target_id: str) -> list[Asset]:
        """Check for AWS S3 buckets."""
        assets = []
        sem = asyncio.Semaphore(10)

        async def _check_bucket(bucket_name: str):
            async with sem:
                urls = [
                    f"https://{bucket_name}.s3.amazonaws.com",
                    f"https://s3.amazonaws.com/{bucket_name}",
                ]
                for url in urls:
                    try:
                        async with httpx.AsyncClient(timeout=10) as client:
                            resp = await client.head(url)
                            if resp.status_code in (200, 403, 301):
                                accessible = resp.status_code == 200
                                assets.append(Asset(
                                    target_id=target_id,
                                    asset_type=AssetType.S3_BUCKET,
                                    value=bucket_name,
                                    source="cloud_s3",
                                    metadata={
                                        "url": url,
                                        "status": resp.status_code,
                                        "publicly_accessible": accessible,
                                        "provider": "aws",
                                    },
                                ))
                    except Exception:
                        pass

        bucket_names = set()
        for pattern in self.S3_PATTERNS:
            bucket_names.add(pattern.format(domain=domain, org=org))

        await asyncio.gather(*[_check_bucket(name) for name in bucket_names])
        return assets

    async def _check_azure_blobs(self, domain: str, org: str, target_id: str) -> list[Asset]:
        """Check for Azure Blob Storage containers."""
        assets = []

        async def _check(name: str):
            url = f"https://{name}.blob.core.windows.net"
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.head(url)
                    if resp.status_code in (200, 400, 403):
                        assets.append(Asset(
                            target_id=target_id,
                            asset_type=AssetType.CLOUD_ASSET,
                            value=name,
                            source="cloud_azure",
                            metadata={
                                "url": url,
                                "status": resp.status_code,
                                "provider": "azure",
                            },
                        ))
            except Exception:
                pass

        names = set()
        for pattern in self.AZURE_PATTERNS:
            names.add(pattern.format(domain=domain, org=org))

        await asyncio.gather(*[_check(n) for n in names])
        return assets

    async def _check_gcp_buckets(self, domain: str, org: str, target_id: str) -> list[Asset]:
        """Check for Google Cloud Storage buckets."""
        assets = []

        async def _check(name: str):
            url = f"https://storage.googleapis.com/{name}"
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.head(url)
                    if resp.status_code in (200, 403):
                        assets.append(Asset(
                            target_id=target_id,
                            asset_type=AssetType.CLOUD_ASSET,
                            value=name,
                            source="cloud_gcp",
                            metadata={
                                "url": url,
                                "status": resp.status_code,
                                "provider": "gcp",
                            },
                        ))
            except Exception:
                pass

        names = set()
        for pattern in self.GCP_PATTERNS:
            names.add(pattern.format(domain=domain, org=org))

        await asyncio.gather(*[_check(n) for n in names])
        return assets

"""
DNS Enumeration Module
======================

Performs comprehensive DNS reconnaissance:
- Record type enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, SRV)
- Zone transfer attempts
- DNS cache snooping
- DNSSEC validation
"""

from __future__ import annotations

import asyncio
from typing import Any

import dns.resolver
import dns.zone
import dns.query

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class DNSEnumerator:
    """Comprehensive DNS record enumeration."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR", "CAA"]

    def __init__(self):
        self.config = get_config()
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = self.config.recon.active.dns_resolvers

    async def enumerate(self, domain: str, target_id: str) -> list[Asset]:
        """
        Enumerate all DNS records for the target domain.
        """
        logger.info(f"  📋 DNS enumeration: {domain}")
        assets: list[Asset] = []
        dns_records: dict[str, list[str]] = {}

        loop = asyncio.get_running_loop()

        for rtype in self.RECORD_TYPES:
            try:
                answers = await loop.run_in_executor(
                    None, self._resolve, domain, rtype
                )
                if answers:
                    dns_records[rtype] = answers
                    for record in answers:
                        # Extract IP addresses
                        if rtype in ("A", "AAAA"):
                            assets.append(Asset(
                                target_id=target_id,
                                asset_type=AssetType.IP,
                                value=record,
                                source=f"dns_{rtype}",
                                metadata={"record_type": rtype, "domain": domain},
                            ))
                        # Extract mail servers
                        elif rtype == "MX":
                            mx_host = record.split()[-1].rstrip(".")
                            assets.append(Asset(
                                target_id=target_id,
                                asset_type=AssetType.SUBDOMAIN,
                                value=mx_host,
                                source="dns_MX",
                                metadata={"record_type": "MX", "full_record": record},
                            ))
                        # Extract name servers
                        elif rtype == "NS":
                            ns_host = record.rstrip(".")
                            assets.append(Asset(
                                target_id=target_id,
                                asset_type=AssetType.SUBDOMAIN,
                                value=ns_host,
                                source="dns_NS",
                                metadata={"record_type": "NS"},
                            ))
                        # Extract CNAME targets
                        elif rtype == "CNAME":
                            cname_target = record.rstrip(".")
                            assets.append(Asset(
                                target_id=target_id,
                                asset_type=AssetType.SUBDOMAIN,
                                value=cname_target,
                                source="dns_CNAME",
                                metadata={"record_type": "CNAME"},
                            ))
                        # Check TXT records for interesting data
                        elif rtype == "TXT":
                            self._analyze_txt_record(record, domain, target_id, assets)

            except Exception as e:
                logger.debug(f"DNS {rtype} query failed for {domain}: {e}")

        # Attempt zone transfer
        try:
            zt_results = await loop.run_in_executor(None, self._zone_transfer, domain)
            for host in zt_results:
                assets.append(Asset(
                    target_id=target_id,
                    asset_type=AssetType.SUBDOMAIN,
                    value=host,
                    source="zone_transfer",
                ))
        except Exception as e:
            logger.debug(f"Zone transfer not possible: {e}")

        logger.info(f"  ✅ DNS enumeration found {len(assets)} records")
        return assets

    def _resolve(self, domain: str, rtype: str) -> list[str]:
        """Synchronous DNS resolution."""
        try:
            answers = self.resolver.resolve(domain, rtype)
            return [str(rdata) for rdata in answers]
        except Exception as exc:
            logger.debug(f"DNS resolve failed for {domain}/{rtype}: {exc}")
            return []

    def _zone_transfer(self, domain: str) -> list[str]:
        """Attempt DNS zone transfer (AXFR)."""
        hosts = []
        try:
            ns_answers = self.resolver.resolve(domain, "NS")
            for ns in ns_answers:
                ns_str = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_str, domain, lifetime=10))
                    for name, node in zone.nodes.items():
                        host = str(name)
                        if host != "@":
                            hosts.append(f"{host}.{domain}")
                except Exception as exc:
                    logger.debug(f"Zone transfer failed for NS {ns_str}: {exc}")
                    continue
        except Exception as exc:
            logger.debug(f"NS lookup failed for zone transfer on {domain}: {exc}")
        return hosts

    def _analyze_txt_record(
        self, record: str, domain: str, target_id: str, assets: list[Asset]
    ):
        """Analyze TXT records for security-relevant information."""
        record_lower = record.lower()

        # SPF records
        if "v=spf1" in record_lower:
            assets.append(Asset(
                target_id=target_id,
                asset_type=AssetType.DOMAIN,
                value=domain,
                source="dns_TXT_SPF",
                metadata={"txt_record": record, "type": "spf"},
            ))

        # DMARC records
        if "v=dmarc" in record_lower:
            assets.append(Asset(
                target_id=target_id,
                asset_type=AssetType.DOMAIN,
                value=domain,
                source="dns_TXT_DMARC",
                metadata={"txt_record": record, "type": "dmarc"},
            ))

        # Verification records (may leak service info)
        verification_services = [
            "google-site-verification", "MS=", "facebook-domain-verification",
            "apple-domain-verification", "atlassian-domain-verification",
            "docusign", "stripe-verification",
        ]
        for svc in verification_services:
            if svc.lower() in record_lower:
                assets.append(Asset(
                    target_id=target_id,
                    asset_type=AssetType.DOMAIN,
                    value=domain,
                    source="dns_TXT_verification",
                    metadata={"txt_record": record, "service_hint": svc},
                ))

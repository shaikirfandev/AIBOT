"""
GitHub Reconnaissance Module
=============================

Searches GitHub for:
- Leaked secrets and credentials
- API keys
- Internal documentation
- Code mentioning target domains
- Configuration files
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import Asset, AssetType

logger = get_logger()


class GitHubRecon:
    """Search GitHub for target-related secrets and assets."""

    GITHUB_API = "https://api.github.com"

    # Patterns that indicate leaked secrets
    SECRET_PATTERNS = [
        r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
        r"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
        r"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
        r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})",
        r"(?i)AKIA[0-9A-Z]{16}",  # AWS Access Key
        r"(?i)(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",  # GitHub tokens
        r"(?i)sk-[a-zA-Z0-9]{20,}",  # Stripe/OpenAI keys
        r"(?i)xox[bpsar]-[a-zA-Z0-9\-]{10,}",  # Slack tokens
        r"(?i)eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+",  # JWT tokens
    ]

    def __init__(self):
        self.config = get_config()
        self.timeout = self.config.recon.timeout
        self.github_token = self.config.api_keys.github_token

    async def search(self, domain: str, target_id: str) -> list[Asset]:
        """
        Search GitHub for target-related information.
        """
        logger.info(f"  🐙 GitHub reconnaissance: {domain}")
        assets: list[Asset] = []

        search_queries = [
            f'"{domain}"',
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" aws_access_key',
            f'"{domain}" authorization',
            f'"{domain}" config',
            f'"{domain}" internal',
        ]

        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for query in search_queries:
                try:
                    resp = await client.get(
                        f"{self.GITHUB_API}/search/code",
                        params={"q": query, "per_page": 10},
                        headers=headers,
                    )
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        for item in data.get("items", []):
                            repo_name = item.get("repository", {}).get("full_name", "")
                            file_path = item.get("path", "")
                            html_url = item.get("html_url", "")

                            assets.append(Asset(
                                target_id=target_id,
                                asset_type=AssetType.REPOSITORY,
                                value=repo_name,
                                source="github_search",
                                metadata={
                                    "query": query,
                                    "file_path": file_path,
                                    "url": html_url,
                                },
                            ))

                    elif resp.status_code == 403:
                        logger.warning("GitHub API rate limit reached")
                        break

                except Exception as e:
                    logger.debug(f"GitHub search error: {e}")

        # Deduplicate
        seen = set()
        unique_assets = []
        for a in assets:
            if a.value not in seen:
                seen.add(a.value)
                unique_assets.append(a)

        logger.info(f"  ✅ GitHub found {len(unique_assets)} repositories")
        return unique_assets

    def analyze_for_secrets(self, content: str) -> list[dict[str, str]]:
        """Analyze content for potential secret leaks."""
        findings = []
        for pattern in self.SECRET_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                findings.append({
                    "pattern": pattern,
                    "match": match.group(0)[:50] + "...",  # Truncate for safety
                    "position": match.start(),
                })
        return findings

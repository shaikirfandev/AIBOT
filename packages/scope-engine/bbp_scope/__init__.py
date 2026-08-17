"""Scope & Policy Enforcement Engine.

Every agent action must pass through this engine before execution:
  Authorization Check → Scope Check → Policy Check → Rate Limit Check → Tool Permission Check → Execute
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import time
from collections import defaultdict
from threading import Lock
from typing import Optional
from urllib.parse import urlparse

from bbp_schemas.core import ScopePolicy, ScopeRule


class ScopeViolation(Exception):
    """Raised when an action violates scope or policy."""


class RateLimitExceeded(Exception):
    """Raised when rate limits are exceeded."""


class _TokenBucket:
    """Simple token-bucket rate limiter."""

    def __init__(self, rate: int, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = float(capacity)
        self.last = time.monotonic()
        self._lock = Lock()

    def acquire(self) -> bool:
        with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


class ScopeEngine:
    """Central Scope & Policy Enforcement Engine."""

    def __init__(self, scope: ScopeRule, policy: ScopePolicy):
        self.scope = scope
        self.policy = policy
        self._request_count = 0
        self._rate_limiter = _TokenBucket(policy.max_requests_per_second, policy.max_requests_per_second * 2)
        self._concurrent = 0
        self._concurrent_lock = Lock()
        self._audit: list[dict] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_target(self, url: str) -> None:
        """Full authorization pipeline for a URL target."""
        self._check_authorization(url)
        self._check_scope(url)
        self._check_policy(url)
        self._check_rate_limit()
        self._log_audit("target_check", url, allowed=True)

    def check_action(self, action: str) -> None:
        """Verify that an action is not prohibited."""
        if action.lower() in [p.lower() for p in self.policy.prohibited_actions]:
            self._log_audit("action_blocked", action, allowed=False)
            raise ScopeViolation(f"Prohibited action: {action}")

    def check_tool_permission(self, tool: str, permissions: list[str]) -> None:
        """Verify a tool has the required permissions."""
        if tool not in permissions and "*" not in permissions:
            raise ScopeViolation(f"Tool '{tool}' not in permitted tools: {permissions}")

    def acquire_concurrency(self) -> bool:
        """Acquire a concurrency slot. Returns False if at limit."""
        with self._concurrent_lock:
            if self._concurrent >= self.policy.max_concurrent_requests:
                return False
            self._concurrent += 1
            return True

    def release_concurrency(self) -> None:
        with self._concurrent_lock:
            self._concurrent = max(0, self._concurrent - 1)

    @property
    def audit_log(self) -> list[dict]:
        return list(self._audit)

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_authorization(self, url: str) -> None:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        if not domain:
            raise ScopeViolation(f"Cannot determine domain from URL: {url}")

    def _check_scope(self, url: str) -> None:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path or "/"

        # Check excluded domains
        for excl in self.scope.excluded_domains:
            if fnmatch.fnmatch(domain, excl):
                raise ScopeViolation(f"Domain {domain} is excluded from scope")

        # Check excluded paths
        for excl in self.scope.excluded_paths:
            if fnmatch.fnmatch(path, excl):
                raise ScopeViolation(f"Path {path} is excluded from scope")

        # Must match at least one allowed domain/subdomain/url/ip
        if not self._matches_allowed(url):
            raise ScopeViolation(f"URL {url} is not within allowed scope")

        # Check port
        port = parsed.port
        if port and self.scope.ports and port not in self.scope.ports:
            raise ScopeViolation(f"Port {port} is not in allowed ports")

        # Check protocol
        scheme = parsed.scheme or "https"
        if self.scope.protocols and scheme not in self.scope.protocols:
            raise ScopeViolation(f"Protocol {scheme} is not allowed")

    def _matches_allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        domain = parsed.hostname or ""

        # Check domains
        for d in self.scope.domains:
            if fnmatch.fnmatch(domain, d) or domain.endswith("." + d):
                return True

        # Check subdomains
        for s in self.scope.subdomains:
            if fnmatch.fnmatch(domain, s):
                return True

        # Check URLs
        for u in self.scope.urls:
            if url.startswith(u):
                return True

        # Check IP ranges
        try:
            ip = ipaddress.ip_address(domain)
            for cidr in self.scope.ip_ranges:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass

        return False

    def _check_policy(self, url: str) -> None:
        if self._request_count >= self.policy.max_total_requests:
            raise ScopeViolation(f"Request budget exhausted ({self.policy.max_total_requests})")

    def _check_rate_limit(self) -> None:
        if not self._rate_limiter.acquire():
            raise RateLimitExceeded("Rate limit exceeded")
        self._request_count += 1

    def _log_audit(self, action: str, target: str, allowed: bool) -> None:
        self._audit.append({
            "action": action,
            "target": target,
            "allowed": allowed,
            "timestamp": time.time(),
            "request_count": self._request_count,
        })


def create_finding_fingerprint(
    asset: str, endpoint: str, parameter: str, vuln_class: str, component: str = ""
) -> str:
    """Create a deterministic fingerprint for finding deduplication."""
    raw = f"{asset}|{endpoint}|{parameter}|{vuln_class}|{component}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

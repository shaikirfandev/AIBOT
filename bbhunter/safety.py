"""
Authorization & Safety Gate.
Ensures that ALL operations are performed only against authorized targets.
"""

from __future__ import annotations

import fnmatch
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from bbhunter.config import get_config
from bbhunter.logger import get_action_logger, get_logger
from bbhunter.models import Authorization, ScopeRule, Target

logger = get_logger()
action_logger = get_action_logger()


class AuthorizationError(Exception):
    """Raised when an operation targets an unauthorized asset."""
    pass


class SafetyGate:
    """
    Central authorization and safety enforcement.
    
    Every engine MUST call SafetyGate.check() before performing
    any action against a target. If authorization is not confirmed,
    the operation is blocked.
    """

    def __init__(self):
        self.config = get_config()
        self.authorized_targets: list[Target] = []
        self._load_authorized_targets()

    def _load_authorized_targets(self):
        """Load authorized targets from the YAML file."""
        auth_file = Path(self.config.safety.authorization_file)
        if not auth_file.exists():
            logger.warning(f"Authorization file not found: {auth_file}")
            return

        with open(auth_file) as f:
            data = yaml.safe_load(f) or {}

        targets_data = data.get("targets", [])
        if not targets_data:
            logger.info("No authorized targets configured.")
            return

        for t in targets_data:
            target = Target(
                domain=t.get("domain", ""),
                scope=ScopeRule(**t.get("scope", {})),
                authorization=Authorization(**t.get("authorization", {})),
                rules=t.get("rules", {}),
            )
            self.authorized_targets.append(target)

        logger.info(f"Loaded {len(self.authorized_targets)} authorized target(s)")

    def is_target_authorized(self, domain: str) -> bool:
        """Check if a domain/host is in the authorized targets list."""
        if not self.config.safety.require_authorization:
            return True

        for target in self.authorized_targets:
            # Direct match
            if domain == target.domain:
                return True
            # Check include scope patterns
            for pattern in target.scope.include:
                if fnmatch.fnmatch(domain, pattern):
                    # Verify not excluded
                    excluded = any(
                        fnmatch.fnmatch(domain, exc)
                        for exc in target.scope.exclude
                    )
                    if not excluded:
                        return True
        return False

    def is_url_in_scope(self, url: str, target: Target) -> bool:
        """Check if a URL is within scope for a given target."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Check inclusion
        in_scope = False
        for pattern in target.scope.include:
            if fnmatch.fnmatch(hostname, pattern):
                in_scope = True
                break

        if not in_scope and hostname == target.domain:
            in_scope = True

        # Check exclusion
        if in_scope:
            for pattern in target.scope.exclude:
                if fnmatch.fnmatch(hostname, pattern):
                    return False

        return in_scope

    def check(self, domain: str, action: str = "scan") -> Target:
        """
        Verify authorization before any action.
        
        Raises AuthorizationError if the target is not authorized.
        Returns the matching Target object.
        """
        if not self.config.safety.require_authorization:
            # Return a permissive target for testing
            action_logger.log("authorization_bypass", domain, {"action": action, "reason": "authorization_disabled"})
            return Target(domain=domain)

        for target in self.authorized_targets:
            if self.is_target_authorized(domain):
                # Check expiry
                if target.authorization.expiry_date:
                    try:
                        expiry = datetime.strptime(target.authorization.expiry_date, "%Y-%m-%d")
                        if datetime.utcnow() > expiry:
                            raise AuthorizationError(
                                f"Authorization for {domain} expired on {target.authorization.expiry_date}"
                            )
                    except ValueError:
                        pass

                action_logger.log("authorization_granted", domain, {"action": action})
                logger.info(f"✅ Authorization confirmed for: {domain}")
                return target

        action_logger.log("authorization_denied", domain, {"action": action}, level="ERROR")
        raise AuthorizationError(
            f"❌ Target '{domain}' is NOT authorized for security testing.\n"
            f"Add it to {self.config.safety.authorization_file} with proper authorization details."
        )

    def get_rate_limit(self, domain: str) -> int:
        """Get the rate limit for a specific target."""
        for target in self.authorized_targets:
            if fnmatch.fnmatch(domain, target.domain) or domain == target.domain:
                return target.rules.get("rate_limit_rps", self.config.safety.rate_limit_rps)
        return self.config.safety.rate_limit_rps

    def is_method_banned(self, method: str) -> bool:
        """Check if a testing method is banned."""
        return method.lower() in self.config.safety.banned_methods


# Singleton
_safety_gate: SafetyGate | None = None


def get_safety_gate() -> SafetyGate:
    global _safety_gate
    if _safety_gate is None:
        _safety_gate = SafetyGate()
    return _safety_gate

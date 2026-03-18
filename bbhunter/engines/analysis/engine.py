"""
Intelligent Analysis Engine (v2 – Intelligence Upgrade)
========================================================

AI-powered vulnerability analysis:
- ML-integrated false positive reduction (delegates to LearningEngine)
- Contextual correlation (same param across endpoints, tech-aware)
- Vulnerability chaining with dynamic chain discovery
- CVSS 3.1 base-score estimation
- Temporal analysis (new vs. previously seen)
- Enhanced attack-graph generation with impact propagation
"""

from __future__ import annotations

import hashlib
import html
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import (
    ExploitChain,
    Severity,
    Vulnerability,
    VulnCategory,
)

logger = get_logger()


# ───────────────────────────────────────────────────────────
#  CVSS 3.1 Base-Score Estimation
# ───────────────────────────────────────────────────────────

# Simplified CVSS 3.1 mapping per category (Attack Vector, Complexity, Privs, User Interaction, Scope, CIA)
_CVSS_CATEGORY_DEFAULTS: dict[VulnCategory, dict[str, float]] = {
    VulnCategory.SQLI:               {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "S": 1.0, "C": 0.56, "I": 0.56, "A": 0.56},
    VulnCategory.XSS:                {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.62, "S": 1.0, "C": 0.22, "I": 0.22, "A": 0.0},
    VulnCategory.SSRF:               {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "S": 1.0, "C": 0.56, "I": 0.22, "A": 0.0},
    VulnCategory.SSTI:               {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "S": 1.0, "C": 0.56, "I": 0.56, "A": 0.56},
    VulnCategory.COMMAND_INJECTION:  {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "S": 1.0, "C": 0.56, "I": 0.56, "A": 0.56},
    VulnCategory.IDOR:               {"AV": 0.85, "AC": 0.77, "PR": 0.62, "UI": 0.85, "S": 0.0, "C": 0.56, "I": 0.22, "A": 0.0},
    VulnCategory.AUTH_BYPASS:        {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "S": 1.0, "C": 0.56, "I": 0.56, "A": 0.22},
    VulnCategory.JWT:                {"AV": 0.85, "AC": 0.44, "PR": 0.85, "UI": 0.85, "S": 1.0, "C": 0.56, "I": 0.56, "A": 0.0},
    VulnCategory.OPEN_REDIRECT:      {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.62, "S": 0.0, "C": 0.22, "I": 0.22, "A": 0.0},
    VulnCategory.CORS:               {"AV": 0.85, "AC": 0.44, "PR": 0.85, "UI": 0.62, "S": 0.0, "C": 0.22, "I": 0.22, "A": 0.0},
    VulnCategory.PATH_TRAVERSAL:     {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.85, "S": 0.0, "C": 0.56, "I": 0.0,  "A": 0.0},
    VulnCategory.CSRF:               {"AV": 0.85, "AC": 0.77, "PR": 0.85, "UI": 0.62, "S": 0.0, "C": 0.0,  "I": 0.22, "A": 0.0},
}


def estimate_cvss(vuln: Vulnerability) -> float:
    """
    Estimate a CVSS 3.1 base score from vulnerability metadata.

    This is a heuristic—real CVSS requires manual assessment—but gives a
    reasonable numeric score for ranking.
    """
    defaults = _CVSS_CATEGORY_DEFAULTS.get(vuln.category)
    if not defaults:
        return _severity_to_cvss(vuln.severity)

    av = defaults["AV"]
    ac = defaults["AC"]
    pr = defaults["PR"]
    ui = defaults["UI"]
    s_changed = defaults["S"] > 0
    c = defaults["C"]
    i = defaults["I"]
    a = defaults["A"]

    # Adjust based on metadata
    if vuln.url and ("auth" in vuln.url.lower() or "login" in vuln.url.lower()):
        pr = max(pr - 0.15, 0.27)  # lower privilege needed → higher score component
    if vuln.confidence > 0.9:
        ac = min(ac + 0.1, 0.77)   # high confidence → lower complexity → higher sub-score

    # ISS (Impact Sub-Score)
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if s_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if s_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    return round(score, 1)


def _severity_to_cvss(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5, Severity.HIGH: 7.5,
        Severity.MEDIUM: 5.0, Severity.LOW: 2.5,
        Severity.INFORMATIONAL: 0.0,
    }.get(severity, 5.0)


# ───────────────────────────────────────────────────────────
#  Chain Patterns
# ───────────────────────────────────────────────────────────

CHAIN_PATTERNS = [
    {
        "name": "Account Takeover Chain",
        "required": [VulnCategory.IDOR, VulnCategory.AUTH_BYPASS],
        "severity": Severity.CRITICAL,
        "impact": "Full account takeover: IDOR exposes user data, combined with auth bypass enables impersonation.",
    },
    {
        "name": "XSS to Account Takeover",
        "required": [VulnCategory.XSS, VulnCategory.CSRF],
        "severity": Severity.CRITICAL,
        "impact": "XSS enables CSRF bypass, allowing state-changing actions on behalf of victims.",
    },
    {
        "name": "SSRF to Cloud Credential Theft",
        "required": [VulnCategory.SSRF, VulnCategory.CLOUD_MISCONFIG],
        "severity": Severity.CRITICAL,
        "impact": "SSRF accesses cloud metadata, leaking IAM credentials for full cloud compromise.",
    },
    {
        "name": "SQLi to Full Compromise",
        "required": [VulnCategory.SQLI],
        "severity": Severity.CRITICAL,
        "impact": "SQL injection enables data extraction, authentication bypass, and potential OS command execution.",
    },
    {
        "name": "Open Redirect + OAuth Token Theft",
        "required": [VulnCategory.OPEN_REDIRECT],
        "severity": Severity.HIGH,
        "impact": "Open redirect in OAuth flow allows stealing authorization codes/tokens.",
    },
    {
        "name": "SSTI to RCE",
        "required": [VulnCategory.SSTI],
        "severity": Severity.CRITICAL,
        "impact": "Template injection enables arbitrary code execution on the server.",
    },
    {
        "name": "JWT Forgery + Privilege Escalation",
        "required": [VulnCategory.JWT, VulnCategory.ACCESS_CONTROL],
        "severity": Severity.CRITICAL,
        "impact": "JWT weakness allows token forgery, combined with broken access control for admin access.",
    },
    {
        "name": "IDOR + Information Disclosure",
        "required": [VulnCategory.IDOR, VulnCategory.INFORMATION_DISCLOSURE],
        "severity": Severity.HIGH,
        "impact": "IDOR combined with info disclosure allows mass user data extraction.",
    },
    {
        "name": "CORS + XSS Data Exfiltration",
        "required": [VulnCategory.CORS, VulnCategory.XSS],
        "severity": Severity.HIGH,
        "impact": "Misconfigured CORS with XSS enables cross-origin data theft.",
    },
    # ── New v2 chain patterns ──
    {
        "name": "SSRF to Internal Network Pivot",
        "required": [VulnCategory.SSRF],
        "severity": Severity.HIGH,
        "impact": "SSRF allows scanning internal services, port mapping, and pivoting into internal network.",
    },
    {
        "name": "XSS + Open Redirect → Phishing",
        "required": [VulnCategory.XSS, VulnCategory.OPEN_REDIRECT],
        "severity": Severity.HIGH,
        "impact": "XSS combined with open redirect creates convincing phishing that steals credentials.",
    },
    {
        "name": "Path Traversal → Source Code Leak",
        "required": [VulnCategory.PATH_TRAVERSAL],
        "severity": Severity.HIGH,
        "impact": "Path traversal enables reading server source code, config files, and secrets.",
    },
    {
        "name": "IDOR + CSRF → Mass Account Modification",
        "required": [VulnCategory.IDOR, VulnCategory.CSRF],
        "severity": Severity.CRITICAL,
        "impact": "IDOR with CSRF allows an attacker to modify any user's data without authentication.",
    },
    {
        "name": "Auth Bypass + SQLi → Full Database Dump",
        "required": [VulnCategory.AUTH_BYPASS, VulnCategory.SQLI],
        "severity": Severity.CRITICAL,
        "impact": "Authentication bypass gives SQLi access to admin-level queries, enabling full database exfiltration.",
    },
    {
        "name": "Command Injection → RCE",
        "required": [VulnCategory.COMMAND_INJECTION],
        "severity": Severity.CRITICAL,
        "impact": "OS command injection enables arbitrary command execution with web server privileges.",
    },
    {
        "name": "JWT + IDOR → Horizontal Privilege Escalation",
        "required": [VulnCategory.JWT, VulnCategory.IDOR],
        "severity": Severity.CRITICAL,
        "impact": "JWT manipulation with IDOR allows accessing and modifying other users' resources.",
    },
]


class AnalysisEngine:
    """
    Intelligent vulnerability analysis engine.

    Thinks like a human bug bounty hunter:
    - Reduces false positives (heuristic + ML)
    - Chains vulnerabilities for maximum impact
    - Assesses real-world exploitability with CVSS estimation
    - Correlates findings across endpoints
    - Generates rich attack graphs
    """

    def __init__(self):
        self.config = get_config()
        self._learning_engine: Any = None
        self._historical_hashes: set[str] = set()

    def set_learning_engine(self, engine: Any):
        """Inject a LearningEngine for ML-based FP prediction."""
        self._learning_engine = engine

    def load_history(self, past_vulns: list[Vulnerability]):
        """Load previously-seen findings for temporal deduplication."""
        for v in past_vulns:
            self._historical_hashes.add(self._vuln_fingerprint(v))

    # ───────────────────────────────────────────────────────
    #  Main entry points
    # ───────────────────────────────────────────────────────

    async def run(self, vulnerabilities: list[Vulnerability]) -> dict[str, Any]:
        """Async entry point used by dashboard and CLI."""
        return self.analyze(vulnerabilities)

    def analyze(self, vulnerabilities: list[Vulnerability]) -> dict[str, Any]:
        """Comprehensive analysis pipeline."""
        logger.info(f"🧠 Analyzing {len(vulnerabilities)} findings...")

        # Step 1: False positive reduction (heuristic + ML)
        verified = self.reduce_false_positives(vulnerabilities)
        logger.info(f"  After FP reduction: {len(verified)} findings")

        # Step 2: CVSS estimation & severity recalculation
        for vuln in verified:
            vuln.cvss_score = estimate_cvss(vuln)
            vuln.severity = self.assess_severity(vuln)

        # Step 3: Contextual correlation
        correlations = self.correlate_findings(verified)

        # Step 4: Chain detection (static patterns + dynamic discovery)
        chains = self.detect_chains(verified)
        chains.extend(self.discover_dynamic_chains(verified))
        logger.info(f"  Exploit chains found: {len(chains)}")

        # Step 5: Temporal analysis (flag new vs. known)
        new_findings, known_findings = self.temporal_split(verified)

        # Step 6: Impact assessment
        impact_summary = self.assess_impact(verified, chains)

        # Step 7: Prioritization
        prioritized = self.prioritize(verified)

        # Step 8: Attack graph
        attack_graph = self.generate_attack_graph(verified, chains)

        return {
            "verified_vulnerabilities": prioritized,
            "exploit_chains": chains,
            "correlations": correlations,
            "impact_summary": impact_summary,
            "attack_graph": attack_graph,
            "new_findings": len(new_findings),
            "known_findings": len(known_findings),
            "statistics": {
                "total_findings": len(vulnerabilities),
                "after_fp_reduction": len(verified),
                "critical": sum(1 for v in verified if v.severity == Severity.CRITICAL),
                "high": sum(1 for v in verified if v.severity == Severity.HIGH),
                "medium": sum(1 for v in verified if v.severity == Severity.MEDIUM),
                "low": sum(1 for v in verified if v.severity == Severity.LOW),
                "chains": len(chains),
                "avg_cvss": round(sum(v.cvss_score for v in verified) / max(len(verified), 1), 1),
            },
        }

    # ───────────────────────────────────────────────────────
    #  False Positive Reduction
    # ───────────────────────────────────────────────────────

    def reduce_false_positives(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Filter FPs using threshold + heuristic + ML prediction."""
        threshold = self.config.analysis.false_positive_threshold
        verified: list[Vulnerability] = []

        for vuln in vulns:
            # 1) Confidence threshold
            if vuln.confidence < threshold:
                vuln.false_positive = True
                logger.debug(f"  FP (low confidence): {vuln.title}")
                continue

            # 2) Heuristic checks
            if self._is_likely_fp(vuln):
                vuln.false_positive = True
                logger.debug(f"  FP (heuristic): {vuln.title}")
                continue

            # 3) ML prediction from LearningEngine (if available)
            if self._learning_engine is not None:
                try:
                    tp_prob = self._learning_engine.predict_false_positive(vuln)
                    if tp_prob < 0.3:  # <30% chance of being true positive
                        vuln.false_positive = True
                        vuln.metadata["ml_tp_probability"] = tp_prob
                        logger.debug(f"  FP (ML: {tp_prob:.2f}): {vuln.title}")
                        continue
                    vuln.metadata["ml_tp_probability"] = tp_prob
                except Exception as exc:
                    logger.debug(f"ML FP scoring failed for {vuln.title}: {exc}")

            verified.append(vuln)

        return verified

    def _is_likely_fp(self, vuln: Vulnerability) -> bool:
        """Apply heuristic rules to detect false positives."""
        # XSS: properly encoded
        if vuln.category == VulnCategory.XSS:
            if vuln.evidence and vuln.payload:
                if html.escape(vuln.payload) in vuln.evidence and vuln.payload not in vuln.evidence:
                    return True
            # Reflection inside JSON with escaped content
            if vuln.response and '"' not in vuln.payload and "application/json" in vuln.response[:200]:
                return True

        # SQLi: generic error pages
        if vuln.category == VulnCategory.SQLI:
            if vuln.evidence and len(vuln.evidence) < 20:
                return True
            # Check if same error for any input (heuristic: very short evidence)
            if vuln.response:
                error_keywords = ["syntax error", "sql", "mysql", "postgres", "oracle", "sqlite", "odbc"]
                has_sql_error = any(kw in vuln.response.lower() for kw in error_keywords)
                if not has_sql_error and vuln.confidence < 0.7:
                    return True

        # SSRF: generic error with no internal data
        if vuln.category == VulnCategory.SSRF:
            if vuln.evidence and len(vuln.evidence) < 15:
                return True

        # Very short evidence is suspicious for all categories
        if vuln.evidence and len(vuln.evidence) < 10:
            return True

        # Duplicate canary still encoded
        if vuln.payload and vuln.evidence:
            if urllib_safe(vuln.payload) in vuln.evidence and vuln.payload not in vuln.evidence:
                return True

        return False

    # ───────────────────────────────────────────────────────
    #  Contextual Correlation
    # ───────────────────────────────────────────────────────

    def correlate_findings(self, vulns: list[Vulnerability]) -> list[dict[str, Any]]:
        """
        Find correlated findings—same parameter vulnerable across endpoints,
        same category on same host, technology patterns.
        """
        correlations: list[dict[str, Any]] = []

        # Group by parameter name
        param_groups: dict[str, list[Vulnerability]] = defaultdict(list)
        for v in vulns:
            if v.parameter:
                param_groups[v.parameter].append(v)

        for param_name, group in param_groups.items():
            if len(group) >= 2:
                categories = {v.category for v in group}
                urls = [v.url for v in group]
                correlations.append({
                    "type": "same_parameter",
                    "parameter": param_name,
                    "count": len(group),
                    "categories": [c.value for c in categories],
                    "urls": urls[:10],
                    "insight": (
                        f"Parameter '{param_name}' is vulnerable to {', '.join(c.value for c in categories)} "
                        f"across {len(group)} endpoints — may indicate a shared backend handler."
                    ),
                })

        # Group by URL path prefix (same controller)
        from urllib.parse import urlparse
        path_groups: dict[str, list[Vulnerability]] = defaultdict(list)
        for v in vulns:
            if v.url:
                parsed = urlparse(v.url)
                prefix = "/".join(parsed.path.strip("/").split("/")[:2])
                if prefix:
                    path_groups[prefix].append(v)

        for path, group in path_groups.items():
            if len(group) >= 3:
                categories = {v.category for v in group}
                if len(categories) >= 2:
                    correlations.append({
                        "type": "same_path_prefix",
                        "path_prefix": f"/{path}",
                        "count": len(group),
                        "categories": [c.value for c in categories],
                        "insight": (
                            f"Path /{path} has {len(group)} vulnerabilities across "
                            f"{len(categories)} categories — high-value attack surface."
                        ),
                    })

        # Severity clustering
        crits = [v for v in vulns if v.severity in (Severity.CRITICAL, Severity.HIGH)]
        if len(crits) >= 3:
            domains = set()
            for v in crits:
                if v.url:
                    domains.add(urlparse(v.url).netloc)
            correlations.append({
                "type": "critical_cluster",
                "count": len(crits),
                "domains": list(domains)[:5],
                "insight": f"{len(crits)} high/critical findings — suggests weak security posture.",
            })

        return correlations

    # ───────────────────────────────────────────────────────
    #  Chain Detection
    # ───────────────────────────────────────────────────────

    def detect_chains(self, vulns: list[Vulnerability]) -> list[ExploitChain]:
        """Detect known vulnerability chain patterns."""
        chains: list[ExploitChain] = []
        vuln_categories = {v.category for v in vulns}
        vuln_by_category: dict[VulnCategory, list[Vulnerability]] = defaultdict(list)
        for v in vulns:
            vuln_by_category[v.category].append(v)

        for pattern in CHAIN_PATTERNS:
            required = set(pattern["required"])
            if required.issubset(vuln_categories):
                chain_vulns: list[Vulnerability] = []
                for cat in required:
                    chain_vulns.extend(vuln_by_category.get(cat, []))
                if chain_vulns:
                    chain = ExploitChain(
                        target_id=chain_vulns[0].target_id,
                        title=pattern["name"],
                        description=pattern["impact"],
                        vulnerability_ids=[v.id for v in chain_vulns],
                        combined_severity=pattern["severity"],
                        impact=pattern["impact"],
                        attack_path=[v.title for v in chain_vulns],
                    )
                    chains.append(chain)
                    for v in chain_vulns:
                        v.chain_ids.append(chain.id)
        return chains

    def discover_dynamic_chains(self, vulns: list[Vulnerability]) -> list[ExploitChain]:
        """
        Dynamically discover chains not in static patterns.

        Looks for vulns on the SAME endpoint/parameter that can be combined.
        """
        chains: list[ExploitChain] = []
        from urllib.parse import urlparse

        # Group by (host, path)
        endpoint_groups: dict[str, list[Vulnerability]] = defaultdict(list)
        for v in vulns:
            if v.url:
                parsed = urlparse(v.url)
                key = f"{parsed.netloc}{parsed.path}"
                endpoint_groups[key].append(v)

        for endpoint, group in endpoint_groups.items():
            if len(group) < 2:
                continue
            categories = {v.category for v in group}
            # Multi-vuln on same endpoint = natural chain
            if len(categories) >= 2:
                max_sev = max(group, key=lambda v: _severity_rank(v.severity))
                chain = ExploitChain(
                    target_id=group[0].target_id,
                    title=f"Multi-Vuln on {endpoint[:60]}",
                    description=(
                        f"Same endpoint vulnerable to {', '.join(c.value for c in categories)} "
                        f"— test chaining these for higher impact."
                    ),
                    vulnerability_ids=[v.id for v in group],
                    combined_severity=max_sev.severity,
                    impact=f"Multiple vulnerabilities at same endpoint amplify each other.",
                    attack_path=[v.title for v in group],
                )
                chains.append(chain)

        return chains

    # ───────────────────────────────────────────────────────
    #  Temporal Analysis
    # ───────────────────────────────────────────────────────

    def temporal_split(
        self, vulns: list[Vulnerability]
    ) -> tuple[list[Vulnerability], list[Vulnerability]]:
        """Separate new findings from previously-seen ones."""
        new_finds: list[Vulnerability] = []
        known: list[Vulnerability] = []
        for v in vulns:
            fp = self._vuln_fingerprint(v)
            if fp in self._historical_hashes:
                v.metadata["temporal_status"] = "known"
                known.append(v)
            else:
                v.metadata["temporal_status"] = "new"
                new_finds.append(v)
        return new_finds, known

    @staticmethod
    def _vuln_fingerprint(v: Vulnerability) -> str:
        raw = f"{v.category.value}|{v.url}|{v.parameter}|{v.payload}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    # ───────────────────────────────────────────────────────
    #  Severity & Impact
    # ───────────────────────────────────────────────────────

    def assess_severity(self, vuln: Vulnerability) -> Severity:
        """Recalculate severity based on CVSS score and context."""
        # Use CVSS if available
        if vuln.cvss_score >= 9.0:
            return Severity.CRITICAL
        elif vuln.cvss_score >= 7.0:
            return Severity.HIGH
        elif vuln.cvss_score >= 4.0:
            return Severity.MEDIUM
        elif vuln.cvss_score >= 0.1:
            return Severity.LOW
        elif vuln.cvss_score == 0.0 and vuln.severity == Severity.INFORMATIONAL:
            return Severity.INFORMATIONAL

        # Fallback to rule-based
        base = vuln.severity
        if not vuln.url or "auth" not in vuln.url.lower():
            if base == Severity.MEDIUM:
                return Severity.HIGH
        if vuln.category in (VulnCategory.SQLI, VulnCategory.SSTI, VulnCategory.COMMAND_INJECTION):
            if vuln.confidence > 0.8:
                return Severity.CRITICAL
        return base

    def assess_impact(
        self, vulns: list[Vulnerability], chains: list[ExploitChain],
    ) -> dict[str, Any]:
        """Generate overall impact assessment."""
        impacts = {
            "data_breach_risk": False,
            "account_takeover_risk": False,
            "rce_risk": False,
            "privilege_escalation_risk": False,
            "financial_risk": False,
            "supply_chain_risk": False,
            "pii_exposure_risk": False,
        }
        for vuln in vulns:
            if vuln.category in (VulnCategory.SQLI, VulnCategory.IDOR, VulnCategory.PATH_TRAVERSAL):
                impacts["data_breach_risk"] = True
            if vuln.category in (VulnCategory.AUTH_BYPASS, VulnCategory.JWT):
                impacts["account_takeover_risk"] = True
            if vuln.category in (VulnCategory.SSTI, VulnCategory.COMMAND_INJECTION):
                impacts["rce_risk"] = True
            if vuln.category in (VulnCategory.ACCESS_CONTROL, VulnCategory.API_PRIVESC):
                impacts["privilege_escalation_risk"] = True
            if vuln.category == VulnCategory.INFORMATION_DISCLOSURE:
                impacts["pii_exposure_risk"] = True
        if any(v.severity == Severity.CRITICAL for v in vulns):
            impacts["financial_risk"] = True
        # Chain amplification
        for chain in chains:
            if "rce" in chain.title.lower() or "command" in chain.title.lower():
                impacts["rce_risk"] = True
                impacts["supply_chain_risk"] = True
        return impacts

    def prioritize(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Prioritize by CVSS score, then severity, then confidence."""
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1,
            Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFORMATIONAL: 4,
        }
        return sorted(
            vulns,
            key=lambda v: (severity_order.get(v.severity, 5), -v.cvss_score, -v.confidence),
        )

    # ───────────────────────────────────────────────────────
    #  Attack Graph
    # ───────────────────────────────────────────────────────

    def generate_attack_graph(
        self, vulns: list[Vulnerability], chains: list[ExploitChain],
    ) -> dict[str, Any]:
        """Generate an attack graph showing exploit paths and impact propagation."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        # Vulnerability nodes
        for vuln in vulns:
            nodes.append({
                "id": vuln.id,
                "label": vuln.title[:60],
                "type": "vulnerability",
                "severity": vuln.severity.value,
                "category": vuln.category.value,
                "cvss": vuln.cvss_score,
                "is_new": vuln.metadata.get("temporal_status") == "new",
            })

        # Chain nodes and edges
        for chain in chains:
            nodes.append({
                "id": chain.id,
                "label": chain.title[:60],
                "type": "chain",
                "severity": chain.combined_severity.value,
            })
            for vuln_id in chain.vulnerability_ids:
                edges.append({
                    "source": vuln_id,
                    "target": chain.id,
                    "label": "contributes_to",
                })

        # Impact nodes (derived from chains)
        impact_categories: set[str] = set()
        for chain in chains:
            title_lower = chain.title.lower()
            impact_lower = chain.impact.lower()
            if "takeover" in title_lower:
                impact_categories.add("Account Takeover")
            if "rce" in title_lower or "code execution" in impact_lower or "command" in title_lower:
                impact_categories.add("Remote Code Execution")
            if "data" in impact_lower or "exfiltration" in impact_lower:
                impact_categories.add("Data Breach")
            if "credential" in impact_lower or "token" in impact_lower:
                impact_categories.add("Credential Theft")
            if "pivot" in impact_lower or "internal" in impact_lower:
                impact_categories.add("Internal Network Access")

        for impact in impact_categories:
            impact_id = f"impact_{impact.lower().replace(' ', '_')}"
            nodes.append({"id": impact_id, "label": impact, "type": "impact"})
            # Connect relevant chains
            for chain in chains:
                if impact.lower().split()[0] in chain.impact.lower():
                    edges.append({
                        "source": chain.id,
                        "target": impact_id,
                        "label": "leads_to",
                    })

        return {"nodes": nodes, "edges": edges}


# ───────────────────────────────────────────────────────────
#  Helpers
# ───────────────────────────────────────────────────────────

def _severity_rank(s: Severity) -> int:
    return {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
            Severity.LOW: 1, Severity.INFORMATIONAL: 0}.get(s, 0)


def urllib_safe(payload: str) -> str:
    """URL-encode a payload for comparison purposes."""
    import urllib.parse
    return urllib.parse.quote(payload, safe="")

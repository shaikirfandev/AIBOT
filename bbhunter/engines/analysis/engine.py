"""
Intelligent Analysis Engine
==============================

AI-powered vulnerability analysis:
- False positive reduction
- Vulnerability chaining
- Exploitability analysis
- Impact assessment
- Attack graph generation
"""

from __future__ import annotations

import re
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


class AnalysisEngine:
    """
    Intelligent vulnerability analysis engine.
    
    Thinks like a human bug bounty hunter:
    - Reduces false positives
    - Chains vulnerabilities for maximum impact
    - Assesses real-world exploitability
    - Generates attack graphs
    """

    # Vulnerability chain patterns (vuln A + vuln B → higher impact)
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
    ]

    # False positive indicators
    FP_PATTERNS = {
        VulnCategory.XSS: [
            "payload is html-encoded in response",
            "payload appears inside a comment",
            "response is application/json with escaped content",
        ],
        VulnCategory.SQLI: [
            "error message is a generic 500",
            "error does not contain SQL keywords",
            "site returns same error for any input",
        ],
        VulnCategory.SSRF: [
            "response is a generic error page",
            "no internal data in response",
        ],
    }

    def __init__(self):
        self.config = get_config()

    def analyze(self, vulnerabilities: list[Vulnerability]) -> dict[str, Any]:
        """
        Perform comprehensive analysis on scan results.
        
        Returns:
            Dictionary with analyzed results, chains, and recommendations.
        """
        logger.info(f"🧠 Analyzing {len(vulnerabilities)} findings...")

        # Step 1: False positive reduction
        verified = self.reduce_false_positives(vulnerabilities)
        logger.info(f"  After FP reduction: {len(verified)} findings")

        # Step 2: Recalculate severity
        for vuln in verified:
            vuln.severity = self.assess_severity(vuln)

        # Step 3: Chain detection
        chains = self.detect_chains(verified)
        logger.info(f"  Exploit chains found: {len(chains)}")

        # Step 4: Impact assessment
        impact_summary = self.assess_impact(verified, chains)

        # Step 5: Prioritization
        prioritized = self.prioritize(verified)

        # Step 6: Generate attack graph
        attack_graph = self.generate_attack_graph(verified, chains)

        return {
            "verified_vulnerabilities": prioritized,
            "exploit_chains": chains,
            "impact_summary": impact_summary,
            "attack_graph": attack_graph,
            "statistics": {
                "total_findings": len(vulnerabilities),
                "after_fp_reduction": len(verified),
                "critical": sum(1 for v in verified if v.severity == Severity.CRITICAL),
                "high": sum(1 for v in verified if v.severity == Severity.HIGH),
                "medium": sum(1 for v in verified if v.severity == Severity.MEDIUM),
                "low": sum(1 for v in verified if v.severity == Severity.LOW),
                "chains": len(chains),
            },
        }

    def reduce_false_positives(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Filter out likely false positives based on confidence and heuristics."""
        threshold = self.config.analysis.false_positive_threshold
        verified = []

        for vuln in vulns:
            # Skip very low confidence
            if vuln.confidence < threshold:
                vuln.false_positive = True
                logger.debug(f"  FP: {vuln.title} (confidence: {vuln.confidence:.2f})")
                continue

            # Additional heuristic checks
            if self._is_likely_fp(vuln):
                vuln.false_positive = True
                logger.debug(f"  FP (heuristic): {vuln.title}")
                continue

            verified.append(vuln)

        return verified

    def _is_likely_fp(self, vuln: Vulnerability) -> bool:
        """Apply heuristic rules to detect false positives."""
        # XSS: Check if response properly encodes
        if vuln.category == VulnCategory.XSS:
            if vuln.evidence:
                import html
                if html.escape(vuln.payload) in vuln.evidence:
                    return True

        # SQLi: Generic error pages
        if vuln.category == VulnCategory.SQLI:
            if vuln.evidence and len(vuln.evidence) < 20:
                return True

        # Very short evidence is suspicious
        if vuln.evidence and len(vuln.evidence) < 10:
            return True

        return False

    def detect_chains(self, vulns: list[Vulnerability]) -> list[ExploitChain]:
        """Detect vulnerability chains for maximum impact."""
        chains = []
        vuln_categories = {v.category for v in vulns}
        vuln_by_category: dict[VulnCategory, list[Vulnerability]] = {}
        
        for v in vulns:
            vuln_by_category.setdefault(v.category, []).append(v)

        for pattern in self.CHAIN_PATTERNS:
            required = set(pattern["required"])
            if required.issubset(vuln_categories):
                # Build chain from matching vulnerabilities
                chain_vulns = []
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

                    # Update linked vulns
                    for v in chain_vulns:
                        v.chain_ids.append(chain.id)

        return chains

    def assess_severity(self, vuln: Vulnerability) -> Severity:
        """Recalculate severity based on context and exploitability."""
        base_severity = vuln.severity

        # Upgrade if authentication is not required
        if not vuln.url or "auth" not in vuln.url.lower():
            if base_severity == Severity.MEDIUM:
                return Severity.HIGH

        # Upgrade critical categories
        if vuln.category in (VulnCategory.SQLI, VulnCategory.SSTI, VulnCategory.COMMAND_INJECTION):
            if vuln.confidence > 0.8:
                return Severity.CRITICAL

        return base_severity

    def assess_impact(
        self, vulns: list[Vulnerability], chains: list[ExploitChain]
    ) -> dict[str, Any]:
        """Generate overall impact assessment."""
        impacts = {
            "data_breach_risk": False,
            "account_takeover_risk": False,
            "rce_risk": False,
            "privilege_escalation_risk": False,
            "financial_risk": False,
        }

        for vuln in vulns:
            if vuln.category in (VulnCategory.SQLI, VulnCategory.IDOR):
                impacts["data_breach_risk"] = True
            if vuln.category in (VulnCategory.AUTH_BYPASS, VulnCategory.JWT):
                impacts["account_takeover_risk"] = True
            if vuln.category in (VulnCategory.SSTI, VulnCategory.COMMAND_INJECTION):
                impacts["rce_risk"] = True
            if vuln.category in (VulnCategory.ACCESS_CONTROL, VulnCategory.API_PRIVESC):
                impacts["privilege_escalation_risk"] = True

        # Any critical finding implies financial risk
        if any(v.severity == Severity.CRITICAL for v in vulns):
            impacts["financial_risk"] = True

        return impacts

    def prioritize(self, vulns: list[Vulnerability]) -> list[Vulnerability]:
        """Prioritize vulnerabilities by severity and confidence."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }
        return sorted(vulns, key=lambda v: (severity_order.get(v.severity, 5), -v.confidence))

    def generate_attack_graph(
        self, vulns: list[Vulnerability], chains: list[ExploitChain]
    ) -> dict[str, Any]:
        """Generate an attack graph showing exploit paths."""
        nodes = []
        edges = []

        # Add vulnerability nodes
        for vuln in vulns:
            nodes.append({
                "id": vuln.id,
                "label": vuln.title,
                "type": "vulnerability",
                "severity": vuln.severity.value,
                "category": vuln.category.value,
            })

        # Add chain nodes and edges
        for chain in chains:
            nodes.append({
                "id": chain.id,
                "label": chain.title,
                "type": "chain",
                "severity": chain.combined_severity.value,
            })
            for vuln_id in chain.vulnerability_ids:
                edges.append({
                    "source": vuln_id,
                    "target": chain.id,
                    "label": "contributes_to",
                })

        # Add impact nodes
        impact_categories = set()
        for chain in chains:
            if "takeover" in chain.title.lower():
                impact_categories.add("Account Takeover")
            if "rce" in chain.title.lower() or "code execution" in chain.impact.lower():
                impact_categories.add("Remote Code Execution")
            if "data" in chain.impact.lower():
                impact_categories.add("Data Breach")

        for impact in impact_categories:
            impact_id = f"impact_{impact.lower().replace(' ', '_')}"
            nodes.append({
                "id": impact_id,
                "label": impact,
                "type": "impact",
            })

        return {"nodes": nodes, "edges": edges}

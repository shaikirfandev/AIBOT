"""
External Tool Runner
=====================

Wraps external CLI tools (subfinder, nuclei, sqlmap, ffuf, etc.)
and feeds their output back into BBHunter's data models.

Each tool wrapper:
1. Checks if the tool is installed
2. Runs the tool with proper arguments
3. Parses output (JSON / line-based)
4. Converts results into BBHunter models (Asset, Endpoint, Vulnerability)
5. Returns structured data to the calling engine

All tools respect the SafetyGate — only authorized targets are allowed.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bbhunter.logger import get_logger
from bbhunter.safety import SafetyGate
from bbhunter.models import (
    Asset, AssetType, Endpoint, Vulnerability,
    VulnCategory, Severity, ScanStatus,
)

logger = get_logger()
safety = SafetyGate()


# ─── Utility ────────────────────────────────────────────────────────────

def tool_exists(name: str) -> bool:
    """Check if an external tool is installed and on PATH."""
    return shutil.which(name) is not None


async def run_cmd(
    cmd: list[str],
    timeout: int = 600,
    cwd: str | None = None,
) -> tuple[str, str, int]:
    """Run a shell command asynchronously and return (stdout, stderr, returncode)."""
    logger.info(f"🔧 Running: {' '.join(cmd[:5])}{'…' if len(cmd) > 5 else ''}")
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return "", f"Command timed out after {timeout}s", -1
    return (
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
        proc.returncode or 0,
    )


@dataclass
class ToolResult:
    """Generic result container from an external tool run."""
    tool: str
    success: bool
    raw_output: str = ""
    parsed: list[dict[str, Any]] = field(default_factory=list)
    assets: list[Asset] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    error: str = ""


# ═══════════════════════════════════════════════════════════════════════
#  RECONNAISSANCE TOOLS
# ═══════════════════════════════════════════════════════════════════════

class SubfinderRunner:
    """
    Wrapper for ProjectDiscovery's subfinder.
    Passive subdomain enumeration using 40+ sources.
    """
    TOOL = "subfinder"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("subfinder")

    async def run(self, domain: str, **kwargs) -> ToolResult:
        safety.check(domain)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed. Run: install_tools.sh"
            return result

        cmd = ["subfinder", "-d", domain, "-silent", "-json"]
        if kwargs.get("recursive"):
            cmd.append("-recursive")
        if kwargs.get("sources"):
            cmd.extend(["-sources", ",".join(kwargs["sources"])])

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        if rc != 0:
            result.error = stderr
            return result

        result.success = True
        result.raw_output = stdout
        for line in stdout.strip().splitlines():
            try:
                data = json.loads(line)
                host = data.get("host", line.strip())
                result.parsed.append(data)
                result.assets.append(Asset(
                    target_id="ext", value=host, asset_type=AssetType.SUBDOMAIN, source="subfinder",
                ))
            except json.JSONDecodeError:
                host = line.strip()
                if host:
                    result.assets.append(Asset(
                        target_id="ext", value=host, asset_type=AssetType.SUBDOMAIN, source="subfinder",
                    ))
        logger.info(f"✅ subfinder found {len(result.assets)} subdomains for {domain}")
        return result


class AmassRunner:
    """Wrapper for OWASP Amass — advanced subdomain enumeration."""
    TOOL = "amass"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("amass")

    async def run(self, domain: str, mode: str = "enum", **kwargs) -> ToolResult:
        safety.check(domain)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
            tmp_path = tmp.name

        cmd = ["amass", mode, "-d", domain, "-json", tmp_path, "-silent"]
        if kwargs.get("passive"):
            cmd.append("-passive")
        if kwargs.get("timeout"):
            cmd.extend(["-timeout", str(kwargs["timeout"])])

        _, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 600))

        try:
            raw = Path(tmp_path).read_text()
            result.raw_output = raw
            for line in raw.strip().splitlines():
                try:
                    data = json.loads(line)
                    name = data.get("name", "")
                    if name:
                        result.parsed.append(data)
                        result.assets.append(Asset(
                            target_id="ext", value=name, asset_type=AssetType.SUBDOMAIN, source="amass",
                        ))
                except json.JSONDecodeError:
                    pass
            result.success = True
            logger.info(f"✅ amass found {len(result.assets)} subdomains for {domain}")
        except FileNotFoundError:
            result.error = f"amass output file not found. stderr: {stderr}"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        return result


class GauRunner:
    """Wrapper for gau — Get All URLs from Wayback, CC, OTX, URLScan."""
    TOOL = "gau"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("gau")

    async def run(self, domain: str, **kwargs) -> ToolResult:
        safety.check(domain)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        cmd = ["gau", "--subs", domain]
        if kwargs.get("providers"):
            cmd.extend(["--providers", ",".join(kwargs["providers"])])

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        result.raw_output = stdout
        result.success = rc == 0
        for line in stdout.strip().splitlines():
            url = line.strip()
            if url:
                result.parsed.append({"url": url})
                result.endpoints.append(Endpoint(target_id="ext", url=url, method="GET", metadata={"source": "gau"}))
        logger.info(f"✅ gau found {len(result.endpoints)} URLs for {domain}")
        return result


class WaybackurlsRunner:
    """Wrapper for waybackurls — fetch known URLs from Wayback Machine."""
    TOOL = "waybackurls"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("waybackurls")

    async def run(self, domain: str, **kwargs) -> ToolResult:
        safety.check(domain)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        proc = await asyncio.create_subprocess_exec(
            "waybackurls", domain,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        stdout = stdout_bytes.decode(errors="replace")
        result.raw_output = stdout
        result.success = True
        for line in stdout.strip().splitlines():
            url = line.strip()
            if url:
                result.endpoints.append(Endpoint(target_id="ext", url=url, method="GET", metadata={"source": "waybackurls"}))
        logger.info(f"✅ waybackurls found {len(result.endpoints)} URLs for {domain}")
        return result


# ═══════════════════════════════════════════════════════════════════════
#  HTTP PROBING TOOLS
# ═══════════════════════════════════════════════════════════════════════

class HttpxRunner:
    """
    Wrapper for ProjectDiscovery's httpx — HTTP probing & tech detection.
    Takes a list of hosts and probes for live HTTP(S) services.
    """
    TOOL = "httpx"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("httpx")

    async def run(self, hosts: list[str], **kwargs) -> ToolResult:
        for h in hosts:
            safety.check(h)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("\n".join(hosts))
            input_file = f.name

        cmd = [
            "httpx", "-l", input_file, "-silent", "-json",
            "-status-code", "-title", "-tech-detect", "-follow-redirects",
        ]
        if kwargs.get("threads"):
            cmd.extend(["-threads", str(kwargs["threads"])])

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        Path(input_file).unlink(missing_ok=True)

        result.raw_output = stdout
        result.success = rc == 0
        for line in stdout.strip().splitlines():
            try:
                data = json.loads(line)
                url = data.get("url", "")
                result.parsed.append(data)
                if url:
                    result.endpoints.append(Endpoint(
                        target_id="ext", url=url, method="GET",
                        status_code=data.get("status_code", 0),
                        technology=data.get("tech", []),
                        metadata={"source": "httpx"},
                    ))
            except json.JSONDecodeError:
                pass
        logger.info(f"✅ httpx probed {len(result.endpoints)} live hosts")
        return result


# ═══════════════════════════════════════════════════════════════════════
#  CONTENT DISCOVERY TOOLS
# ═══════════════════════════════════════════════════════════════════════

class FfufRunner:
    """
    Wrapper for ffuf — fast web fuzzer for directory/parameter discovery.
    """
    TOOL = "ffuf"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("ffuf")

    async def run(
        self,
        url: str,
        wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
        **kwargs,
    ) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        fuzz_url = url.rstrip("/") + "/FUZZ" if "FUZZ" not in url else url
        cmd = [
            "ffuf", "-u", fuzz_url, "-w", wordlist,
            "-o", output_file, "-of", "json",
            "-mc", kwargs.get("match_codes", "200,201,301,302,403"),
            "-s",  # silent
        ]
        if kwargs.get("threads"):
            cmd.extend(["-t", str(kwargs["threads"])])
        if kwargs.get("extensions"):
            cmd.extend(["-e", kwargs["extensions"]])
        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                cmd.extend(["-H", h])

        _, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 600))

        try:
            raw = Path(output_file).read_text()
            result.raw_output = raw
            data = json.loads(raw)
            for entry in data.get("results", []):
                found_url = entry.get("url", "")
                result.parsed.append(entry)
                if found_url:
                    result.endpoints.append(Endpoint(
                        target_id="ext", url=found_url, method="GET",
                        status_code=entry.get("status", 0),
                        metadata={"source": "ffuf"},
                    ))
            result.success = True
            logger.info(f"✅ ffuf found {len(result.endpoints)} paths on {url}")
        except Exception as e:
            result.error = str(e)
        finally:
            Path(output_file).unlink(missing_ok=True)

        return result


class FeroxbusterRunner:
    """Wrapper for feroxbuster — recursive content discovery."""
    TOOL = "feroxbuster"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("feroxbuster")

    async def run(self, url: str, **kwargs) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        cmd = [
            "feroxbuster", "-u", url, "--json", "-o", output_file,
            "--silent", "--depth", str(kwargs.get("depth", 2)),
            "--threads", str(kwargs.get("threads", 50)),
        ]
        if kwargs.get("wordlist"):
            cmd.extend(["-w", kwargs["wordlist"]])

        _, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 600))

        try:
            raw = Path(output_file).read_text()
            result.raw_output = raw
            for line in raw.strip().splitlines():
                try:
                    data = json.loads(line)
                    if data.get("type") == "response":
                        found_url = data.get("url", "")
                        result.parsed.append(data)
                        if found_url:
                            result.endpoints.append(Endpoint(
                                target_id="ext", url=found_url, method="GET",
                                status_code=data.get("status", 0),
                                metadata={"source": "feroxbuster"},
                            ))
                except json.JSONDecodeError:
                    pass
            result.success = True
            logger.info(f"✅ feroxbuster found {len(result.endpoints)} paths on {url}")
        except Exception as e:
            result.error = str(e)
        finally:
            Path(output_file).unlink(missing_ok=True)

        return result


# ═══════════════════════════════════════════════════════════════════════
#  VULNERABILITY SCANNING TOOLS
# ═══════════════════════════════════════════════════════════════════════

class NucleiRunner:
    """
    Wrapper for ProjectDiscovery's Nuclei — template-based vulnerability scanner.
    The single most impactful external tool for bug bounty.
    """
    TOOL = "nuclei"

    SEVERITY_MAP = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }

    CATEGORY_MAP = {
        "xss": VulnCategory.XSS,
        "sqli": VulnCategory.SQLI,
        "ssrf": VulnCategory.SSRF,
        "ssti": VulnCategory.SSTI,
        "lfi": VulnCategory.LFI,
        "rfi": VulnCategory.RFI,
        "rce": VulnCategory.RCE,
        "redirect": VulnCategory.OPEN_REDIRECT,
        "cors": VulnCategory.CORS,
        "cve": VulnCategory.OTHER,
        "exposure": VulnCategory.INFO_DISCLOSURE,
        "misconfiguration": VulnCategory.MISCONFIGURATION,
    }

    @staticmethod
    def is_available() -> bool:
        return tool_exists("nuclei")

    async def run(
        self,
        targets: list[str] | str,
        severity: str = "",
        tags: str = "",
        templates: str = "",
        **kwargs,
    ) -> ToolResult:
        if isinstance(targets, str):
            targets = [targets]
        for t in targets:
            safety.check(t)

        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("\n".join(targets))
            input_file = f.name
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        cmd = [
            "nuclei", "-l", input_file, "-jsonl", "-o", output_file,
            "-silent", "-nc",  # no color
        ]
        if severity:
            cmd.extend(["-severity", severity])
        if tags:
            cmd.extend(["-tags", tags])
        if templates:
            cmd.extend(["-t", templates])
        if kwargs.get("rate_limit"):
            cmd.extend(["-rl", str(kwargs["rate_limit"])])
        if kwargs.get("concurrency"):
            cmd.extend(["-c", str(kwargs["concurrency"])])

        _, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 1800))
        Path(input_file).unlink(missing_ok=True)

        try:
            raw = Path(output_file).read_text()
            result.raw_output = raw
            for line in raw.strip().splitlines():
                try:
                    data = json.loads(line)
                    result.parsed.append(data)

                    info = data.get("info", {})
                    sev_str = info.get("severity", "info").lower()
                    tags_list = info.get("tags", [])

                    # Map nuclei tags to VulnCategory
                    category = VulnCategory.OTHER
                    for tag in tags_list:
                        if tag.lower() in self.CATEGORY_MAP:
                            category = self.CATEGORY_MAP[tag.lower()]
                            break

                    vuln = Vulnerability(
                        target_id="ext",
                        title=info.get("name", data.get("template-id", "Unknown")),
                        category=category,
                        severity=self.SEVERITY_MAP.get(sev_str, Severity.INFO),
                        url=data.get("matched-at", data.get("host", "")),
                        description=info.get("description", ""),
                        evidence=data.get("matcher-name", ""),
                        payload=data.get("extracted-results", [""])[0] if data.get("extracted-results") else "",
                        request=data.get("curl-command", ""),
                    )
                    result.vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    pass
            result.success = True
            logger.info(
                f"✅ nuclei found {len(result.vulnerabilities)} findings "
                f"across {len(targets)} target(s)"
            )
        except Exception as e:
            result.error = str(e)
        finally:
            Path(output_file).unlink(missing_ok=True)

        return result


class SqlmapRunner:
    """
    Wrapper for sqlmap — advanced SQL injection detection & exploitation.
    """
    TOOL = "sqlmap"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("sqlmap")

    async def run(self, url: str, **kwargs) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "sqlmap", "-u", url, "--batch", "--output-dir", tmpdir,
                "--level", str(kwargs.get("level", 1)),
                "--risk", str(kwargs.get("risk", 1)),
                "--threads", str(kwargs.get("threads", 1)),
            ]
            if kwargs.get("data"):
                cmd.extend(["--data", kwargs["data"]])
            if kwargs.get("cookie"):
                cmd.extend(["--cookie", kwargs["cookie"]])
            if kwargs.get("headers"):
                for h in kwargs["headers"]:
                    cmd.extend(["-H", h])
            if kwargs.get("technique"):
                cmd.extend(["--technique", kwargs["technique"]])
            if kwargs.get("tamper"):
                cmd.extend(["--tamper", kwargs["tamper"]])

            stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 600))

            result.raw_output = stdout
            result.success = True

            # Parse sqlmap output for injection points
            vuln_indicators = [
                "is vulnerable",
                "injectable",
                "sqlmap identified the following injection point",
            ]
            if any(indicator in stdout.lower() for indicator in vuln_indicators):
                vuln = Vulnerability(
                    target_id="ext",
                    title=f"SQL Injection — {url}",
                    category=VulnCategory.SQLI,
                    severity=Severity.HIGH,
                    url=url,
                    description="sqlmap confirmed SQL injection vulnerability",
                    evidence=stdout[-2000:],  # last 2KB of output
                )
                result.vulnerabilities.append(vuln)
                logger.info(f"🔴 sqlmap confirmed SQLi on {url}")
            else:
                logger.info(f"✅ sqlmap: no SQLi found on {url}")

        return result


class DalfoxRunner:
    """Wrapper for dalfox — advanced XSS scanner."""
    TOOL = "dalfox"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("dalfox")

    async def run(self, url: str, **kwargs) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        cmd = [
            "dalfox", "url", url,
            "--silence", "--format", "json",
            "--output", output_file,
        ]
        if kwargs.get("cookie"):
            cmd.extend(["--cookie", kwargs["cookie"]])
        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                cmd.extend(["-H", h])
        if kwargs.get("waf"):
            cmd.extend(["--waf-evasion"])

        _, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))

        try:
            raw = Path(output_file).read_text()
            result.raw_output = raw
            for line in raw.strip().splitlines():
                try:
                    data = json.loads(line)
                    result.parsed.append(data)
                    vuln = Vulnerability(
                        target_id="ext",
                        title=f"XSS — {data.get('param', 'unknown param')}",
                        category=VulnCategory.XSS,
                        severity=Severity.HIGH if data.get("type") == "verified" else Severity.MEDIUM,
                        url=data.get("proof_url", url),
                        description=f"dalfox {data.get('type', 'potential')} XSS",
                        payload=data.get("payload", ""),
                        evidence=data.get("proof_url", ""),
                    )
                    result.vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    pass
            result.success = True
            logger.info(f"✅ dalfox found {len(result.vulnerabilities)} XSS on {url}")
        except Exception as e:
            result.error = str(e)
        finally:
            Path(output_file).unlink(missing_ok=True)

        return result


# ═══════════════════════════════════════════════════════════════════════
#  PORT SCANNING TOOLS
# ═══════════════════════════════════════════════════════════════════════

class NmapRunner:
    """Wrapper for nmap — network port scanner & service detection."""
    TOOL = "nmap"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("nmap")

    async def run(self, target: str, **kwargs) -> ToolResult:
        safety.check(target)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False, mode="w") as f:
            output_file = f.name

        ports = kwargs.get("ports", "21,22,25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443,8888,9090")
        cmd = [
            "nmap", "-sV", "-sC", target,
            "-p", ports,
            "-oX", output_file,
            "--open",
            "-T", str(kwargs.get("timing", 4)),
        ]
        if kwargs.get("scripts"):
            cmd.extend(["--script", kwargs["scripts"]])

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 600))
        result.raw_output = stdout
        result.success = rc == 0

        # Parse output line by line for open ports
        for line in stdout.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                parts = line.split()
                port_proto = parts[0] if parts else ""
                state = parts[1] if len(parts) > 1 else ""
                service = parts[2] if len(parts) > 2 else ""
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                result.parsed.append({
                    "port": port_proto, "state": state,
                    "service": service, "version": version,
                })
                result.assets.append(Asset(
                    target_id="ext",
                    value=f"{target}:{port_proto}",
                    asset_type=AssetType.IP,
                    source="nmap",
                    metadata={"service": service, "version": version},
                ))

        Path(output_file).unlink(missing_ok=True)
        logger.info(f"✅ nmap found {len(result.parsed)} open ports on {target}")
        return result


class NaabuRunner:
    """Wrapper for naabu — fast port scanner."""
    TOOL = "naabu"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("naabu")

    async def run(self, target: str, **kwargs) -> ToolResult:
        safety.check(target)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        cmd = ["naabu", "-host", target, "-silent", "-json"]
        if kwargs.get("ports"):
            cmd.extend(["-p", kwargs["ports"]])
        if kwargs.get("top_ports"):
            cmd.extend(["-top-ports", str(kwargs["top_ports"])])

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        result.raw_output = stdout
        result.success = rc == 0

        for line in stdout.strip().splitlines():
            try:
                data = json.loads(line)
                result.parsed.append(data)
                port = data.get("port", "")
                host = data.get("host", target)
                result.assets.append(Asset(
                    target_id="ext",
                    value=f"{host}:{port}",
                    asset_type=AssetType.IP,
                    source="naabu",
                ))
            except json.JSONDecodeError:
                pass
        logger.info(f"✅ naabu found {len(result.parsed)} open ports on {target}")
        return result


# ═══════════════════════════════════════════════════════════════════════
#  SECRET SCANNING TOOLS
# ═══════════════════════════════════════════════════════════════════════

class TrufflehogRunner:
    """Wrapper for trufflehog — deep secret detection in git repos."""
    TOOL = "trufflehog"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("trufflehog")

    async def run(self, repo_url: str, **kwargs) -> ToolResult:
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        cmd = ["trufflehog", "git", repo_url, "--json", "--no-update"]
        if kwargs.get("only_verified"):
            cmd.append("--only-verified")

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 600))
        result.raw_output = stdout
        result.success = rc == 0

        for line in stdout.strip().splitlines():
            try:
                data = json.loads(line)
                result.parsed.append(data)
                result.vulnerabilities.append(Vulnerability(
                    target_id="ext",
                    title=f"Secret Found: {data.get('DetectorName', 'Unknown')}",
                    category=VulnCategory.INFO_DISCLOSURE,
                    severity=Severity.HIGH if data.get("Verified") else Severity.MEDIUM,
                    url=repo_url,
                    description=f"Detected {data.get('DetectorName', '')} secret in {data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown file')}",
                    evidence=data.get("Raw", "")[:200],
                ))
            except json.JSONDecodeError:
                pass
        logger.info(f"✅ trufflehog found {len(result.vulnerabilities)} secrets")
        return result


class GitleaksRunner:
    """Wrapper for gitleaks — git secret scanning."""
    TOOL = "gitleaks"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("gitleaks")

    async def run(self, repo_path: str, **kwargs) -> ToolResult:
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        cmd = [
            "gitleaks", "detect", "--source", repo_path,
            "--report-format", "json", "--report-path", output_file,
            "--no-banner",
        ]

        _, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))

        try:
            raw = Path(output_file).read_text()
            result.raw_output = raw
            findings = json.loads(raw) if raw.strip() else []
            for finding in findings:
                result.parsed.append(finding)
                result.vulnerabilities.append(Vulnerability(
                    target_id="ext",
                    title=f"Secret: {finding.get('Description', 'Unknown')}",
                    category=VulnCategory.INFO_DISCLOSURE,
                    severity=Severity.HIGH,
                    url=f"file://{finding.get('File', '')}",
                    description=finding.get("Description", ""),
                    evidence=finding.get("Match", "")[:200],
                ))
            result.success = True
            logger.info(f"✅ gitleaks found {len(result.vulnerabilities)} secrets")
        except Exception as e:
            result.error = str(e)
        finally:
            Path(output_file).unlink(missing_ok=True)

        return result


# ═══════════════════════════════════════════════════════════════════════
#  PARAMETER DISCOVERY TOOLS
# ═══════════════════════════════════════════════════════════════════════

class ArjunRunner:
    """Wrapper for arjun — HTTP parameter discovery."""
    TOOL = "arjun"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("arjun")

    async def run(self, url: str, **kwargs) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            output_file = f.name

        cmd = ["arjun", "-u", url, "-oJ", output_file]
        if kwargs.get("method"):
            cmd.extend(["-m", kwargs["method"]])
        if kwargs.get("headers"):
            for h in kwargs["headers"]:
                cmd.extend(["--headers", h])

        _, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))

        try:
            raw = Path(output_file).read_text()
            result.raw_output = raw
            data = json.loads(raw) if raw.strip() else {}
            for endpoint_url, params in data.items():
                for param in params:
                    result.parsed.append({"url": endpoint_url, "parameter": param})
            result.success = True
            logger.info(f"✅ arjun found {len(result.parsed)} parameters on {url}")
        except Exception as e:
            result.error = str(e)
        finally:
            Path(output_file).unlink(missing_ok=True)

        return result


class ParamspiderRunner:
    """Wrapper for paramspider — parameter mining from web archives."""
    TOOL = "paramspider"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("paramspider")

    async def run(self, domain: str, **kwargs) -> ToolResult:
        safety.check(domain)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        cmd = ["paramspider", "-d", domain, "--quiet"]

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        result.raw_output = stdout
        result.success = rc == 0

        for line in stdout.strip().splitlines():
            url = line.strip()
            if url and url.startswith("http"):
                result.parsed.append({"url": url})
                result.endpoints.append(Endpoint(target_id="ext", url=url, method="GET", metadata={"source": "paramspider"}))
        logger.info(f"✅ paramspider found {len(result.endpoints)} parameterized URLs for {domain}")
        return result


# ═══════════════════════════════════════════════════════════════════════
#  WAF & TECH DETECTION TOOLS
# ═══════════════════════════════════════════════════════════════════════

class Wafw00fRunner:
    """Wrapper for wafw00f — WAF fingerprinting."""
    TOOL = "wafw00f"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("wafw00f")

    async def run(self, url: str, **kwargs) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        cmd = ["wafw00f", url, "-o-", "-f", "json"]
        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 120))
        result.raw_output = stdout
        result.success = rc == 0

        try:
            data = json.loads(stdout)
            result.parsed = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            for line in stdout.splitlines():
                if "is behind" in line.lower():
                    result.parsed.append({"detected": line.strip()})
        logger.info(f"✅ wafw00f completed for {url}")
        return result


class WhatwebRunner:
    """Wrapper for whatweb — website technology fingerprinting."""
    TOOL = "whatweb"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("whatweb")

    async def run(self, url: str, **kwargs) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        cmd = ["whatweb", url, "--log-json=-", "-q"]
        if kwargs.get("aggression"):
            cmd.extend(["-a", str(kwargs["aggression"])])

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 120))
        result.raw_output = stdout
        result.success = rc == 0

        for line in stdout.strip().splitlines():
            try:
                data = json.loads(line)
                result.parsed.append(data)
            except json.JSONDecodeError:
                pass
        logger.info(f"✅ whatweb completed for {url}")
        return result


# ═══════════════════════════════════════════════════════════════════════
#  CRAWLER TOOLS
# ═══════════════════════════════════════════════════════════════════════

class KatanaRunner:
    """Wrapper for katana — fast web crawler by ProjectDiscovery."""
    TOOL = "katana"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("katana")

    async def run(self, url: str, **kwargs) -> ToolResult:
        safety.check(url)
        result = ToolResult(tool=self.TOOL, success=False)
        if not self.is_available():
            result.error = f"{self.TOOL} not installed."
            return result

        cmd = [
            "katana", "-u", url, "-silent", "-jsonl",
            "-depth", str(kwargs.get("depth", 3)),
            "-jc",  # JS crawl
        ]
        if kwargs.get("headless"):
            cmd.append("-headless")
        if kwargs.get("scope_in"):
            cmd.extend(["-fs", kwargs["scope_in"]])

        stdout, stderr, rc = await run_cmd(cmd, timeout=kwargs.get("timeout", 300))
        result.raw_output = stdout
        result.success = rc == 0

        for line in stdout.strip().splitlines():
            try:
                data = json.loads(line)
                found_url = data.get("request", {}).get("endpoint", "")
                result.parsed.append(data)
                if found_url:
                    result.endpoints.append(Endpoint(
                        target_id="ext", url=found_url,
                        method=data.get("request", {}).get("method", "GET"),
                        metadata={"source": "katana"},
                    ))
            except json.JSONDecodeError:
                url_line = line.strip()
                if url_line:
                    result.endpoints.append(Endpoint(target_id="ext", url=url_line, method="GET", metadata={"source": "katana"}))
        logger.info(f"✅ katana crawled {len(result.endpoints)} URLs from {url}")
        return result


# ═══════════════════════════════════════════════════════════════════════
#  NOTIFICATION TOOL
# ═══════════════════════════════════════════════════════════════════════

class NotifyRunner:
    """Wrapper for ProjectDiscovery's notify — send findings to Slack/Discord/Telegram."""
    TOOL = "notify"

    @staticmethod
    def is_available() -> bool:
        return tool_exists("notify")

    async def send(self, message: str, **kwargs) -> bool:
        if not self.is_available():
            logger.warning("notify not installed — skipping notification")
            return False

        proc = await asyncio.create_subprocess_exec(
            "notify", "-silent",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate(input=message.encode())
        return proc.returncode == 0


# ═══════════════════════════════════════════════════════════════════════
#  MASTER TOOL REGISTRY
# ═══════════════════════════════════════════════════════════════════════

TOOL_REGISTRY: dict[str, dict] = {
    # Recon
    "subfinder":    {"class": SubfinderRunner,    "category": "recon",     "desc": "Passive subdomain enumeration"},
    "amass":        {"class": AmassRunner,        "category": "recon",     "desc": "Advanced subdomain discovery"},
    "gau":          {"class": GauRunner,          "category": "recon",     "desc": "Get All URLs from archives"},
    "waybackurls":  {"class": WaybackurlsRunner,  "category": "recon",     "desc": "Wayback Machine URL fetcher"},
    # HTTP Probing
    "httpx":        {"class": HttpxRunner,        "category": "probing",   "desc": "HTTP probing & tech detection"},
    # Content Discovery
    "ffuf":         {"class": FfufRunner,         "category": "discovery", "desc": "Fast web fuzzer"},
    "feroxbuster":  {"class": FeroxbusterRunner,  "category": "discovery", "desc": "Recursive content discovery"},
    # Vulnerability Scanning
    "nuclei":       {"class": NucleiRunner,       "category": "scanner",   "desc": "Template-based vuln scanner"},
    "sqlmap":       {"class": SqlmapRunner,       "category": "scanner",   "desc": "SQL injection scanner"},
    "dalfox":       {"class": DalfoxRunner,       "category": "scanner",   "desc": "XSS scanner"},
    # Port Scanning
    "nmap":         {"class": NmapRunner,         "category": "network",   "desc": "Network port scanner"},
    "naabu":        {"class": NaabuRunner,        "category": "network",   "desc": "Fast port scanner"},
    # Secret Scanning
    "trufflehog":   {"class": TrufflehogRunner,   "category": "secrets",   "desc": "Git secret detection"},
    "gitleaks":     {"class": GitleaksRunner,     "category": "secrets",   "desc": "Git secret scanning"},
    # Parameter Discovery
    "arjun":        {"class": ArjunRunner,        "category": "params",    "desc": "HTTP parameter discovery"},
    "paramspider":  {"class": ParamspiderRunner,  "category": "params",    "desc": "Parameter mining from archives"},
    # WAF / Tech
    "wafw00f":      {"class": Wafw00fRunner,      "category": "fingerprint", "desc": "WAF fingerprinting"},
    "whatweb":      {"class": WhatwebRunner,      "category": "fingerprint", "desc": "Technology fingerprinting"},
    # Crawler
    "katana":       {"class": KatanaRunner,       "category": "crawler",   "desc": "Fast web crawler with JS"},
    # Notification
    "notify":       {"class": NotifyRunner,       "category": "utility",   "desc": "Finding notifications"},
}


def get_installed_tools() -> dict[str, bool]:
    """Return installation status of all registered tools."""
    return {name: tool_exists(name) for name in TOOL_REGISTRY}


def get_tool_runner(name: str):
    """Get an instance of a tool runner by name."""
    entry = TOOL_REGISTRY.get(name)
    if not entry:
        raise ValueError(f"Unknown tool: {name}")
    return entry["class"]()

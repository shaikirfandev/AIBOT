"""
BBHunter CLI
=============

Command-line interface for the Bug Bounty Automation Suite.

Usage:
    bbhunter recon <domain>
    bbhunter surface <domain>
    bbhunter scan <domain> [--scanners xss,sqli,ssrf]
    bbhunter full <domain>
    bbhunter report <scan_id>
    bbhunter payloads <category> [--context html] [--waf cloudflare]
    bbhunter dashboard
    bbhunter learning stats
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

BANNER = r"""
[bold cyan]
 ____  ____  _   _             _            
| __ )| __ )| | | |_   _ _ __ | |_ ___ _ __ 
|  _ \|  _ \| |_| | | | | '_ \| __/ _ \ '__|
| |_) | |_) |  _  | |_| | | | | ||  __/ |   
|____/|____/|_| |_|\__,_|_| |_|\__\___|_|   
[/]
[dim]Bug Bounty Automation Suite v0.1.0[/]
[dim]⚠️  Authorized targets only[/]
"""


def run_async(coro):
    """Run an async coroutine from sync context."""
    return asyncio.get_event_loop().run_until_complete(coro)


@click.group()
@click.version_option(version="0.1.0", prog_name="bbhunter")
def main():
    """BBHunter – Bug Bounty Automation Suite."""
    pass


# ─── Recon ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("domain")
@click.option("--quick", is_flag=True, help="Quick passive-only recon")
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON file")
def recon(domain: str, quick: bool, output: str | None):
    """Run reconnaissance on a target domain."""
    console.print(BANNER)
    console.print(f"[bold]🔍 Recon target:[/] {domain}\n")

    from bbhunter.safety import SafetyGate
    safety = SafetyGate()
    try:
        safety.check(domain)
    except Exception as e:
        console.print(f"[red]❌ Authorization failed:[/] {e}")
        sys.exit(1)

    from bbhunter.engines.recon.engine import ReconEngine
    engine = ReconEngine()

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Running recon...", total=None)
        if quick:
            results = run_async(engine.quick_recon(domain))
        else:
            results = run_async(engine.run(domain))
        progress.update(task, completed=True)

    # Display results
    table = Table(title="Recon Results")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    for key, val in results.items():
        if isinstance(val, list):
            table.add_row(key, str(len(val)))
        elif isinstance(val, dict):
            table.add_row(key, str(len(val)))
        else:
            table.add_row(key, str(val))
    console.print(table)

    if output:
        Path(output).write_text(json.dumps(results, indent=2, default=str))
        console.print(f"\n[green]✅ Results saved to {output}[/]")


# ─── Surface ────────────────────────────────────────────────────────────

@main.command()
@click.argument("domain")
@click.option("--depth", "-d", default=3, help="Crawl depth")
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON")
def surface(domain: str, depth: int, output: str | None):
    """Map the attack surface of a target."""
    console.print(BANNER)
    console.print(f"[bold]🗺️  Surface mapping:[/] {domain}\n")

    from bbhunter.safety import SafetyGate
    safety = SafetyGate()
    try:
        safety.check(domain)
    except Exception as e:
        console.print(f"[red]❌ Authorization failed:[/] {e}")
        sys.exit(1)

    from bbhunter.engines.surface.engine import SurfaceMappingEngine
    engine = SurfaceMappingEngine()

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Mapping attack surface...", total=None)
        results = run_async(engine.run(domain, []))
        progress.update(task, completed=True)

    table = Table(title="Surface Map")
    table.add_column("Item", style="cyan")
    table.add_column("Details", style="green")
    table.add_row("Endpoints", str(len(results.get("endpoints", []))))
    table.add_row("Technologies", ", ".join(results.get("technologies", [])))
    table.add_row("WAF", str(results.get("waf", "none")))
    console.print(table)

    if output:
        Path(output).write_text(json.dumps(results, indent=2, default=str))
        console.print(f"\n[green]✅ Results saved to {output}[/]")


# ─── Vulnerability Scan ────────────────────────────────────────────────

@main.command()
@click.argument("domain")
@click.option("--scanners", "-s", default="", help="Comma-separated scanner list (xss,sqli,ssrf)")
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON")
def scan(domain: str, scanners: str, output: str | None):
    """Run vulnerability scanner against a target."""
    console.print(BANNER)
    console.print(f"[bold]⚡ Scanning:[/] {domain}\n")

    from bbhunter.safety import SafetyGate
    safety = SafetyGate()
    try:
        safety.check(domain)
    except Exception as e:
        console.print(f"[red]❌ Authorization failed:[/] {e}")
        sys.exit(1)

    from bbhunter.engines.scanner.engine import VulnerabilityScanner
    engine = VulnerabilityScanner()
    scanner_list = [s.strip() for s in scanners.split(",") if s.strip()] or None

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Scanning for vulnerabilities...", total=None)
        results = run_async(engine.run(domain, [], scanners=scanner_list))
        progress.update(task, completed=True)

    vulns = results.get("vulnerabilities", [])
    if vulns:
        table = Table(title=f"Vulnerabilities Found ({len(vulns)})")
        table.add_column("Severity", style="bold")
        table.add_column("Category")
        table.add_column("URL")
        table.add_column("Confidence")
        for v in vulns:
            sev = v.get("severity", "info")
            style = {
                "critical": "red bold",
                "high": "bright_red",
                "medium": "yellow",
                "low": "green",
                "info": "dim",
            }.get(sev, "")
            table.add_row(
                f"[{style}]{sev.upper()}[/]",
                v.get("category", ""),
                v.get("url", "")[:60],
                f"{v.get('confidence', 0):.0%}",
            )
        console.print(table)
    else:
        console.print("[yellow]No vulnerabilities found.[/]")

    if output:
        Path(output).write_text(json.dumps(results, indent=2, default=str))
        console.print(f"\n[green]✅ Results saved to {output}[/]")


# ─── Full Pipeline ──────────────────────────────────────────────────────

@main.command()
@click.argument("domain")
@click.option("--output", "-o", type=click.Path(), help="Save full report to JSON")
def full(domain: str, output: str | None):
    """Run the complete pipeline: recon → surface → scan → analysis → report."""
    console.print(BANNER)
    console.print(f"[bold]🚀 Full pipeline:[/] {domain}\n")

    from bbhunter.safety import SafetyGate
    safety = SafetyGate()
    try:
        safety.check(domain)
    except Exception as e:
        console.print(f"[red]❌ Authorization failed:[/] {e}")
        sys.exit(1)

    from bbhunter.engines.recon.engine import ReconEngine
    from bbhunter.engines.surface.engine import SurfaceMappingEngine
    from bbhunter.engines.scanner.engine import VulnerabilityScanner
    from bbhunter.engines.analysis.engine import AnalysisEngine
    from bbhunter.engines.reporting.engine import ReportEngine

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        # Phase 1
        t1 = progress.add_task("[cyan]Phase 1: Reconnaissance...", total=None)
        recon_results = run_async(ReconEngine().run(domain))
        progress.update(t1, completed=True, description="[green]✅ Recon complete")

        # Phase 2
        t2 = progress.add_task("[cyan]Phase 2: Surface Mapping...", total=None)
        subs = recon_results.get("subdomains", [])
        surface_results = run_async(SurfaceMappingEngine().run(domain, subs))
        progress.update(t2, completed=True, description="[green]✅ Surface mapped")

        # Phase 3
        t3 = progress.add_task("[cyan]Phase 3: Vulnerability Scanning...", total=None)
        endpoints = surface_results.get("endpoints", [])
        scan_results = run_async(VulnerabilityScanner().run(domain, endpoints))
        progress.update(t3, completed=True, description="[green]✅ Scanning complete")

        # Phase 4
        t4 = progress.add_task("[cyan]Phase 4: Analysis...", total=None)
        vulns = scan_results.get("vulnerabilities", [])
        analysis = run_async(AnalysisEngine().run(vulns))
        progress.update(t4, completed=True, description="[green]✅ Analysis complete")

        # Phase 5
        t5 = progress.add_task("[cyan]Phase 5: Report Generation...", total=None)
        report = run_async(ReportEngine().generate_all_reports(domain, analysis))
        progress.update(t5, completed=True, description="[green]✅ Reports generated")

    console.print(Panel(f"[green bold]Pipeline complete for {domain}[/]\n"
                        f"Subdomains: {len(subs)} | Endpoints: {len(endpoints)} | "
                        f"Vulnerabilities: {len(vulns)}",
                        title="Summary"))

    if output:
        full_data = {
            "target": domain,
            "recon": recon_results,
            "surface": surface_results,
            "scan": scan_results,
            "analysis": analysis,
            "report": report,
        }
        Path(output).write_text(json.dumps(full_data, indent=2, default=str))
        console.print(f"\n[green]✅ Full results saved to {output}[/]")


# ─── Payloads ───────────────────────────────────────────────────────────

@main.command()
@click.argument("category", type=click.Choice(["xss", "sqli", "ssrf", "ssti"]))
@click.option("--context", "-c", default="html", help="Injection context")
@click.option("--waf", "-w", default="", help="Target WAF for bypass payloads")
@click.option("--mutate", is_flag=True, help="Apply mutations / WAF bypasses")
def payloads(category: str, context: str, waf: str, mutate: bool):
    """Generate payloads for a vulnerability category."""
    console.print(BANNER)
    from bbhunter.engines.payloads.engine import PayloadEngine
    engine = PayloadEngine()
    result = engine.generate(category=category, context=context, waf=waf or None)
    console.print(f"[bold]💣 {len(result)} payloads generated[/]\n")
    for i, p in enumerate(result, 1):
        console.print(f"  [dim]{i:3d}.[/] {p}")


# ─── Report ─────────────────────────────────────────────────────────────

@main.command()
@click.argument("scan_id")
@click.option("--template", "-t", default="hackerone",
              type=click.Choice(["hackerone", "bugcrowd", "executive"]))
@click.option("--output", "-o", type=click.Path(), help="Output file")
def report(scan_id: str, template: str, output: str | None):
    """Generate a report for a completed scan."""
    console.print(BANNER)
    console.print(f"[bold]📄 Generating {template} report for {scan_id}[/]\n")
    # In a real implementation this would load scan data from DB
    console.print("[yellow]Report generation requires a completed scan.[/]")
    console.print("Use [bold]bbhunter full <domain>[/] first, then generate reports.")


# ─── Dashboard ──────────────────────────────────────────────────────────

@main.command()
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.option("--port", "-p", default=8000, help="Bind port")
def dashboard(host: str, port: int):
    """Launch the web dashboard."""
    console.print(BANNER)
    console.print(f"[bold]🌐 Starting dashboard at http://{host}:{port}[/]\n")
    import uvicorn
    uvicorn.run(
        "bbhunter.engines.dashboard.api:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )


# ─── Learning ──────────────────────────────────────────────────────────

@main.group()
def learning():
    """Learning module commands."""
    pass


@learning.command()
def stats():
    """Show learning module statistics."""
    from bbhunter.engines.learning.engine import LearningEngine
    engine = LearningEngine()
    stats = engine.get_statistics()
    table = Table(title="Learning Module Stats")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    for k, v in stats.items():
        table.add_row(k.replace("_", " ").title(), str(v))
    console.print(table)


@learning.command()
def retrain():
    """Retrain the ML model from all feedback data."""
    from bbhunter.engines.learning.engine import LearningEngine
    engine = LearningEngine()
    engine.train_fp_model()
    console.print("[green]✅ Model retrained[/]")


# ─── Decode ─────────────────────────────────────────────────────────────

@main.command()
@click.argument("data")
def decode(data: str):
    """Decode data (base64, JWT, URL-encoded, hex)."""
    from bbhunter.engines.assistant.engine import ManualTestingAssistant
    assistant = ManualTestingAssistant()
    results = assistant.decode_data(data)
    for fmt, decoded in results.items():
        if decoded:
            console.print(f"[cyan]{fmt}:[/] {decoded}")


# ─── External Tool Commands ────────────────────────────────────────────

@main.group()
def tools():
    """External tool management and execution."""
    pass


@tools.command(name="status")
def tools_status():
    """Show installation status of all external tools."""
    from bbhunter.tools import TOOL_REGISTRY, tool_exists

    table = Table(title="External Tool Status")
    table.add_column("Tool", style="bold")
    table.add_column("Category", style="dim")
    table.add_column("Status")
    table.add_column("Description")

    for name, info in sorted(TOOL_REGISTRY.items()):
        installed = tool_exists(name)
        status = "[green]✓ Installed[/]" if installed else "[red]✗ Missing[/]"
        table.add_row(name, info["category"], status, info["desc"])

    console.print(table)
    installed_count = sum(1 for n in TOOL_REGISTRY if tool_exists(n))
    console.print(f"\n[bold]{installed_count}/{len(TOOL_REGISTRY)}[/] tools installed")


@tools.command(name="run")
@click.argument("tool_name")
@click.argument("target")
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON")
@click.option("--extra", "-e", multiple=True, help="Extra key=value args")
def tools_run(tool_name: str, target: str, output: str | None, extra: tuple):
    """Run an external tool and feed results into BBHunter."""
    console.print(BANNER)
    from bbhunter.tools import get_tool_runner, TOOL_REGISTRY

    if tool_name not in TOOL_REGISTRY:
        console.print(f"[red]Unknown tool: {tool_name}[/]")
        console.print(f"Available: {', '.join(TOOL_REGISTRY.keys())}")
        sys.exit(1)

    runner = get_tool_runner(tool_name)
    if not runner.is_available():
        console.print(f"[red]❌ {tool_name} is not installed.[/]")
        console.print("Run: [bold]sudo ./install_tools.sh[/]")
        sys.exit(1)

    kwargs = {}
    for e in extra:
        if "=" in e:
            k, v = e.split("=", 1)
            kwargs[k] = v

    console.print(f"[bold]🔧 Running {tool_name}[/] against [cyan]{target}[/]\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task(f"Running {tool_name}...", total=None)
        result = run_async(runner.run(target, **kwargs))
        progress.update(task, completed=True)

    if not result.success:
        console.print(f"[red]❌ Error: {result.error}[/]")
        sys.exit(1)

    # Display results
    table = Table(title=f"{tool_name} Results")
    table.add_column("Category", style="cyan")
    table.add_column("Count", style="green")
    if result.assets:
        table.add_row("Assets (subdomains/IPs)", str(len(result.assets)))
    if result.endpoints:
        table.add_row("Endpoints (URLs)", str(len(result.endpoints)))
    if result.vulnerabilities:
        table.add_row("Vulnerabilities", str(len(result.vulnerabilities)))
    if result.parsed:
        table.add_row("Raw findings", str(len(result.parsed)))
    console.print(table)

    # Show vulns if any
    if result.vulnerabilities:
        console.print("")
        vtable = Table(title="Vulnerabilities Found")
        vtable.add_column("Severity", style="bold")
        vtable.add_column("Title")
        vtable.add_column("URL")
        for v in result.vulnerabilities:
            sev_style = {
                Severity.CRITICAL: "red bold", Severity.HIGH: "bright_red",
                Severity.MEDIUM: "yellow", Severity.LOW: "green", Severity.INFO: "dim",
            }.get(v.severity, "")
            vtable.add_row(
                f"[{sev_style}]{v.severity.value.upper()}[/]",
                v.title[:50],
                v.url[:60],
            )
        console.print(vtable)

    if output:
        out_data = {
            "tool": tool_name,
            "target": target,
            "assets": [{"value": a.value, "type": a.asset_type.value, "source": a.source} for a in result.assets],
            "endpoints": [{"url": e.url, "method": e.method, "source": e.metadata.get("source", "")} for e in result.endpoints],
            "vulnerabilities": [
                {"title": v.title, "severity": v.severity.value, "category": v.category.value,
                 "url": v.url, "confidence": v.confidence}
                for v in result.vulnerabilities
            ],
            "raw_count": len(result.parsed),
        }
        Path(output).write_text(json.dumps(out_data, indent=2, default=str))
        console.print(f"\n[green]✅ Results saved to {output}[/]")


@tools.command(name="recon-all")
@click.argument("domain")
@click.option("--output", "-o", type=click.Path(), help="Save combined results to JSON")
def tools_recon_all(domain: str, output: str | None):
    """Run ALL available recon tools against a domain and merge results."""
    console.print(BANNER)
    console.print(f"[bold]🔍 Full external recon:[/] {domain}\n")

    from bbhunter.tools import TOOL_REGISTRY, get_tool_runner

    recon_tools = ["subfinder", "amass", "gau", "waybackurls"]
    all_assets = []
    all_endpoints = []

    for tool_name in recon_tools:
        entry = TOOL_REGISTRY.get(tool_name)
        if not entry:
            continue
        runner = get_tool_runner(tool_name)
        if not runner.is_available():
            console.print(f"  [yellow]⏭ {tool_name} not installed — skipping[/]")
            continue

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
            task = progress.add_task(f"Running {tool_name}...", total=None)
            result = run_async(runner.run(domain))
            progress.update(task, completed=True)

        if result.success:
            all_assets.extend(result.assets)
            all_endpoints.extend(result.endpoints)
            console.print(f"  [green]✓ {tool_name}:[/] {len(result.assets)} assets, {len(result.endpoints)} URLs")
        else:
            console.print(f"  [red]✗ {tool_name}:[/] {result.error}")

    # Deduplicate
    unique_subs = sorted(set(a.value for a in all_assets))
    unique_urls = sorted(set(e.url for e in all_endpoints))

    console.print(Panel(
        f"[green bold]Unique subdomains: {len(unique_subs)}[/]\n"
        f"[green bold]Unique URLs: {len(unique_urls)}[/]",
        title="Combined Results",
    ))

    if output:
        Path(output).write_text(json.dumps({
            "domain": domain,
            "subdomains": unique_subs,
            "urls": unique_urls[:5000],
        }, indent=2))
        console.print(f"\n[green]✅ Combined results saved to {output}[/]")


@tools.command(name="scan-nuclei")
@click.argument("target")
@click.option("--severity", "-s", default="", help="Filter: critical,high,medium,low,info")
@click.option("--tags", "-t", default="", help="Filter by tags: cve,xss,sqli,ssrf")
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON")
def tools_scan_nuclei(target: str, severity: str, tags: str, output: str | None):
    """Run Nuclei template scanner against target(s)."""
    console.print(BANNER)
    from bbhunter.tools import NucleiRunner

    runner = NucleiRunner()
    if not runner.is_available():
        console.print("[red]❌ nuclei not installed. Run: sudo ./install_tools.sh --minimal[/]")
        sys.exit(1)

    console.print(f"[bold]🧬 Nuclei scan:[/] {target}\n")

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Running nuclei...", total=None)
        result = run_async(runner.run(target, severity=severity, tags=tags))
        progress.update(task, completed=True)

    if result.vulnerabilities:
        table = Table(title=f"Nuclei Findings ({len(result.vulnerabilities)})")
        table.add_column("Severity", style="bold")
        table.add_column("Template")
        table.add_column("URL")
        for v in result.vulnerabilities:
            sev = v.severity.value
            style = {"critical": "red bold", "high": "bright_red", "medium": "yellow",
                     "low": "green", "info": "dim"}.get(sev, "")
            table.add_row(f"[{style}]{sev.upper()}[/]", v.title[:40], v.url[:60])
        console.print(table)
    else:
        console.print("[yellow]No findings from nuclei.[/]")

    if output:
        out = [{"title": v.title, "severity": v.severity.value, "url": v.url,
                "category": v.category.value, "confidence": v.confidence}
               for v in result.vulnerabilities]
        Path(output).write_text(json.dumps(out, indent=2))
        console.print(f"\n[green]✅ Results saved to {output}[/]")


@tools.command(name="scan-sqlmap")
@click.argument("url")
@click.option("--level", "-l", default=1, help="SQLMap level (1-5)")
@click.option("--risk", "-r", default=1, help="SQLMap risk (1-3)")
@click.option("--data", "-d", default="", help="POST data")
def tools_scan_sqlmap(url: str, level: int, risk: int, data: str):
    """Run SQLMap against a URL with parameters."""
    console.print(BANNER)
    from bbhunter.tools import SqlmapRunner

    runner = SqlmapRunner()
    if not runner.is_available():
        console.print("[red]❌ sqlmap not installed. Run: sudo ./install_tools.sh[/]")
        sys.exit(1)

    console.print(f"[bold]💉 SQLMap scan:[/] {url}\n")

    kwargs = {"level": level, "risk": risk}
    if data:
        kwargs["data"] = data

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Running sqlmap...", total=None)
        result = run_async(runner.run(url, **kwargs))
        progress.update(task, completed=True)

    if result.vulnerabilities:
        console.print("[red bold]🔴 SQL INJECTION CONFIRMED![/]")
        for v in result.vulnerabilities:
            console.print(f"  URL: {v.url}")
            console.print(f"  Evidence: {v.evidence[:200]}")
    else:
        console.print("[green]No SQL injection found.[/]")


@tools.command(name="fuzz")
@click.argument("url")
@click.option("--wordlist", "-w", default="", help="Custom wordlist path")
@click.option("--extensions", "-e", default="", help="Extensions: php,asp,html")
@click.option("--output", "-o", type=click.Path(), help="Save results to JSON")
def tools_fuzz(url: str, wordlist: str, extensions: str, output: str | None):
    """Run ffuf fuzzer for directory/file discovery."""
    console.print(BANNER)
    from bbhunter.tools import FfufRunner

    runner = FfufRunner()
    if not runner.is_available():
        console.print("[red]❌ ffuf not installed. Run: sudo ./install_tools.sh --minimal[/]")
        sys.exit(1)

    console.print(f"[bold]🔨 Fuzzing:[/] {url}\n")

    kwargs = {}
    if wordlist:
        kwargs["wordlist"] = wordlist
    if extensions:
        kwargs["extensions"] = extensions

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as progress:
        task = progress.add_task("Running ffuf...", total=None)
        result = run_async(runner.run(url, **kwargs) if wordlist else runner.run(url))
        progress.update(task, completed=True)

    if result.endpoints:
        table = Table(title=f"Discovered Paths ({len(result.endpoints)})")
        table.add_column("URL", style="cyan")
        table.add_column("Status")
        for ep in result.endpoints:
            table.add_row(ep.url, str(getattr(ep, 'status_code', '')))
        console.print(table)
    else:
        console.print("[yellow]No paths discovered.[/]")

    if output:
        out = [{"url": e.url, "status": getattr(e, 'status_code', None)} for e in result.endpoints]
        Path(output).write_text(json.dumps(out, indent=2))


# ─── Import Severity for tools commands ─────────────────────────────────
from bbhunter.models import Severity


if __name__ == "__main__":
    main()

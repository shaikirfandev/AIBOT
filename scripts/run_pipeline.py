#!/usr/bin/env python3
"""
BBHunter - Master Orchestrator
================================
Runs the full bug bounty pipeline end-to-end:

  1. Passive Recon (hunt.py)      → data/<target>/
  2. LLM Chunk Analysis           → llm_analysis/<target>/
  3. LLM Report Generation        → reports/<target>/

Designed for low-VRAM setups (8GB or less).
All data flows through files — LLM processes chunk by chunk.

Usage:
    python3 scripts/run_pipeline.py                     # full pipeline
    python3 scripts/run_pipeline.py --phase recon       # recon only
    python3 scripts/run_pipeline.py --phase analyze     # LLM analysis only
    python3 scripts/run_pipeline.py --phase report      # report only
    python3 scripts/run_pipeline.py --resume            # resume from last checkpoint
    python3 scripts/run_pipeline.py --target example.com # different target
"""

import argparse
import json
import logging
import sys
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich import box

console = Console()

sys.path.insert(0, str(Path(__file__).resolve().parent))


def banner():
    console.print(Panel.fit(
        "[bold blue]██████  ██████  ██   ██ ██    ██ ███    ██ ████████[/bold blue]\n"
        "[bold blue]██   ██ ██   ██ ██   ██ ██    ██ ████   ██    ██[/bold blue]\n"
        "[bold blue]██████  ██████  ███████ ██    ██ ██ ██  ██    ██[/bold blue]\n"
        "[bold blue]██   ██ ██   ██ ██   ██ ██    ██ ██  ██ ██    ██[/bold blue]\n"
        "[bold blue]██████  ██████  ██   ██  ██████  ██   ████    ██[/bold blue]\n\n"
        "[bold]Bug Bounty Hunter — Automated Pipeline[/bold]\n"
        "[dim]Recon → LLM Analysis → Engines → Report Generation[/dim]",
        style="blue",
        title="BBHunter",
    ))


def check_prerequisites():
    """Verify all tools and services are available."""
    console.print("\n[bold]🔍 Checking prerequisites…[/bold]\n")
    issues = []

    # Check Go tools
    go_bin = Path.home() / "go" / "bin"
    required_tools = ["subfinder", "gau", "waybackurls", "httpx"]
    optional_tools = ["katana", "hakrawler", "dnsx", "amass"]

    for tool in required_tools:
        path = go_bin / tool
        if path.exists():
            print(f"  ✓ {tool}")
        else:
            print(f"  ✗ {tool} (REQUIRED)")
            issues.append(f"Missing: {tool}. Install: go install github.com/...")

    for tool in optional_tools:
        path = go_bin / tool
        if path.exists():
            print(f"  ✓ {tool}")
        else:
            print(f"  ⚠ {tool} (optional, some steps may skip)")

    # Check system tools
    for tool in ["curl", "dig", "nmap"]:
        if os.path.exists(f"/usr/bin/{tool}"):
            print(f"  ✓ {tool}")
        else:
            print(f"  ⚠ {tool} (optional)")

    # Check Ollama
    try:
        import requests
        resp = requests.get("http://localhost:11434/api/tags", timeout=3,
                            proxies={"http": None, "https": None})
        models = [m["name"] for m in resp.json().get("models", [])]
        print(f"  ✓ Ollama ({len(models)} models loaded)")
    except Exception as exc:
        logging.debug(f"Ollama connectivity check failed: {exc}")
        print(f"  ✗ Ollama not running")
        issues.append("Start Ollama: ollama serve")

    # Check Python deps
    for pkg in ["requests", "yaml", "rich"]:
        try:
            __import__(pkg)
            print(f"  ✓ python:{pkg}")
        except ImportError:
            print(f"  ⚠ python:{pkg} (optional)")

    if issues:
        print(f"\n⚠️  Issues found:")
        for i in issues:
            print(f"  → {i}")
        return False

    print(f"\n✅ All prerequisites OK")
    return True


def run_phase_recon(target: str, resume: bool = False, step_timeout: int = 0):
    """Phase 1: Passive Reconnaissance."""
    console.print(Panel(
        f"[bold]PHASE 1: PASSIVE RECONNAISSANCE[/bold]\nTarget: [cyan]{target}[/cyan]"
        + (f"\n[dim]Step timeout: {step_timeout}s[/dim]" if step_timeout else ""),
        style="blue",
    ))

    # Set target env var and reload config
    os.environ["BB_TARGET"] = target
    import config
    config.reload_target(target)

    from hunt import STEPS, ensure_dirs, log, run_step_with_timeout
    ensure_dirs()

    step_list = list(STEPS.items())
    start = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}[/bold blue]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•  ETA"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Recon", total=len(step_list))
        for name, func in step_list:
            progress.update(task, description=f"[cyan]{name}[/cyan]")
            status = run_step_with_timeout(name, func, step_timeout)
            if status == "⏭":
                console.print(f"  [yellow]⏭ {name} skipped (timeout)[/yellow]")
            elif status == "✗":
                console.print(f"  [red]✗ {name} failed[/red]")
            progress.advance(task)
            time.sleep(1)

    elapsed = time.time() - start
    console.print(f"\n[green]✅ Recon complete in {elapsed:.0f}s ({elapsed/60:.1f}m)[/green]")
    console.print(f"   Data: [cyan]{config.TARGET_DIR}[/cyan]")
    return True


def run_phase_analyze(target: str, resume: bool = False,
                      chunk_timeout: int = 0, max_failures: int = 0):
    """Phase 2: LLM Chunk Analysis."""
    console.print(Panel(
        f"[bold]PHASE 2: LLM CHUNK ANALYSIS[/bold]\nTarget: [cyan]{target}[/cyan]"
        + (f"\n[dim]Chunk timeout: {chunk_timeout}s | Max failures: {max_failures}[/dim]"
           if chunk_timeout or max_failures else ""),
        style="yellow",
    ))

    os.environ["BB_TARGET"] = target

    import config
    config.reload_target(target)

    from llm_analyzer import (
        get_data_files, process_file, check_llm_health, ensure_dirs
    )
    ensure_dirs()

    # Propagate timeout/skip settings into llm_analyzer module
    import llm_analyzer as _llm_mod
    if chunk_timeout:
        _llm_mod._chunk_timeout = chunk_timeout
    if max_failures:
        _llm_mod._max_consecutive_failures = max_failures

    if not check_llm_health():
        console.print("  [red]✗ LLM not available. Start Ollama first.[/red]")
        return False

    files = get_data_files()
    if not files:
        console.print("  [red]✗ No data files. Run recon first.[/red]")
        return False

    console.print(f"  📁 [bold]{len(files)}[/bold] files to analyze\n")
    start = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold yellow]{task.description}[/bold yellow]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•  ETA"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Analyzing", total=len(files))
        for f in files:
            progress.update(task, description=f"[cyan]{f.name}[/cyan]")
            try:
                process_file(f, resume=resume)
            except Exception as e:
                console.print(f"  [red]✗ Error processing {f.name}: {e}[/red]")
            progress.advance(task)

    elapsed = time.time() - start
    console.print(f"\n[green]✅ Analysis complete in {elapsed:.0f}s ({elapsed/60:.1f}m)[/green]")
    console.print(f"   Results: [cyan]{config.TARGET_LLM_DIR}[/cyan]")
    return True


def run_phase_engines(target: str):
    """Phase 3: BBHunter Engine Pipeline (surface, scanner, analysis, payloads, reporting)."""
    console.print(Panel(
        f"[bold]PHASE 3: BBHUNTER ENGINE PIPELINE[/bold]\nTarget: [cyan]{target}[/cyan]",
        style="magenta",
    ))

    os.environ["BB_TARGET"] = target

    import config
    config.reload_target(target)

    try:
        import asyncio
        from engine_bridge import run_all_engines

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold magenta]{task.description}[/bold magenta]"),
            BarColumn(bar_width=40),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Running engines…", total=None)
            asyncio.run(run_all_engines())
            progress.update(task, description="[green]Engines done[/green]", total=1, completed=1)

        console.print(f"\n[green]✅ Engine pipeline complete[/green]")
        return True
    except Exception as e:
        console.print(f"  [red]✗ Engine pipeline failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False


def run_phase_report(target: str, fmt: str = "markdown"):
    """Phase 4: Report Generation."""
    console.print(Panel(
        f"[bold]PHASE 4: REPORT GENERATION[/bold]\nTarget: [cyan]{target}[/cyan]",
        style="green",
    ))

    os.environ["BB_TARGET"] = target

    import config
    config.reload_target(target)

    from generate_report import (
        collect_analyses, extract_findings_from_analyses,
        generate_final_report, save_report, check_llm_health
    )
    config.ensure_dirs()

    if not check_llm_health():
        console.print("  [red]✗ LLM not available[/red]")
        return False

    report_steps = ["Collect analyses", "Extract findings", "Generate report", "Save report"]

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold green]{task.description}[/bold green]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•  ETA"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("Report", total=len(report_steps))

        # Step 1: Collect
        progress.update(task, description="Collecting analyses…")
        analyses = collect_analyses()
        progress.advance(task)
        if not analyses:
            console.print("  [red]✗ No analyses found. Run analyze phase first.[/red]")
            return False
        console.print(f"  📋 {len(analyses)} analyses collected")

        # Step 2: Extract
        progress.update(task, description="Extracting findings…")
        findings = extract_findings_from_analyses(analyses)
        progress.advance(task)
        console.print(f"  📊 {len(findings)} finding blocks extracted")

        # Step 3: Generate
        progress.update(task, description="Generating report via LLM…")
        report = generate_final_report(findings)
        progress.advance(task)

        # Step 4: Save
        progress.update(task, description="Saving report…")
        report_file = save_report(report, findings, fmt=fmt)
        progress.advance(task)

    console.print(f"\n[green]✅ Report saved: [cyan]{report_file}[/cyan][/green]")
    return True


def save_pipeline_state(target: str, phase: str, status: str):
    """Save pipeline state for resume capability."""
    state_file = Path(__file__).resolve().parent.parent / "data" / "pipeline_state.json"
    state_file.parent.mkdir(parents=True, exist_ok=True)

    state = {}
    if state_file.exists():
        state = json.loads(state_file.read_text())

    state[target] = {
        "last_phase": phase,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    state_file.write_text(json.dumps(state, indent=2))


# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="BBHunter - Full Bug Bounty Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/run_pipeline.py                         # full pipeline on default target
  python3 scripts/run_pipeline.py --target example.com    # different target
  python3 scripts/run_pipeline.py --phase recon           # recon only
  python3 scripts/run_pipeline.py --phase analyze --resume # resume LLM analysis
  python3 scripts/run_pipeline.py --phase report --format html
        """,
    )
    parser.add_argument("--target", type=str, default=None, help="Target domain")
    parser.add_argument("--phase", choices=["recon", "analyze", "engines", "report", "all"], default="all")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--format", choices=["markdown", "html"], default="markdown")
    parser.add_argument("--check", action="store_true", help="Check prerequisites only")
    parser.add_argument("--skip-engines", action="store_true",
                        help="Skip the bbhunter engine phase in 'all' mode")
    parser.add_argument("--step-timeout", type=int, default=0,
                        help="Max seconds per recon tool step (0=use config, default=600)")
    parser.add_argument("--chunk-timeout", type=int, default=0,
                        help="Max seconds per LLM chunk (0=use config, default=300)")
    parser.add_argument("--max-failures", type=int, default=0,
                        help="Skip to next file after N consecutive LLM failures (0=use config)")
    args = parser.parse_args()

    banner()

    # Set target
    target = args.target or os.getenv("BB_TARGET", "doordash.com")
    os.environ["BB_TARGET"] = target

    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column(style="bold")
    info_table.add_column(style="cyan")
    info_table.add_row("🎯 Target", target)
    info_table.add_row("📋 Phase", args.phase)
    info_table.add_row("🔄 Resume", str(args.resume))
    info_table.add_row("📄 Format", args.format)
    if args.step_timeout:
        info_table.add_row("⏱  Step timeout", f"{args.step_timeout}s")
    if args.chunk_timeout:
        info_table.add_row("⏱  Chunk timeout", f"{args.chunk_timeout}s")
    if args.max_failures:
        info_table.add_row("⏭  Max failures", str(args.max_failures))
    console.print(info_table)

    # Prerequisites check
    if args.check:
        check_prerequisites()
        return

    if not check_prerequisites():
        console.print("\n[yellow]⚠️  Fix issues above before running the pipeline.[/yellow]")
        console.print("   Use --phase to run individual phases.")
        # Continue anyway for phases that might work

    # ── Build phase plan ──
    all_phases = []
    if args.phase in ("all", "recon"):
        all_phases.append(("recon", "Passive Reconnaissance"))
    if args.phase in ("all", "analyze"):
        all_phases.append(("analyze", "LLM Chunk Analysis"))
    if args.phase in ("all", "engines") and not getattr(args, "skip_engines", False):
        all_phases.append(("engines", "BBHunter Engines"))
    if args.phase in ("all", "report"):
        all_phases.append(("report", "Report Generation"))

    total_start = time.time()
    phase_results: list[dict] = []

    # ── Master progress bar across phases ──
    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}[/bold]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•  ETA"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        master = progress.add_task("Pipeline", total=len(all_phases))

        try:
            for phase_key, phase_label in all_phases:
                progress.update(master, description=f"[cyan]{phase_label}[/cyan]")
                save_pipeline_state(target, phase_key, "running")
                phase_start = time.time()
                success = False

                if phase_key == "recon":
                    success = run_phase_recon(target, args.resume, args.step_timeout)
                elif phase_key == "analyze":
                    success = run_phase_analyze(target, args.resume,
                                                args.chunk_timeout, args.max_failures)
                elif phase_key == "engines":
                    success = run_phase_engines(target)
                elif phase_key == "report":
                    success = run_phase_report(target, args.format)

                elapsed = time.time() - phase_start
                save_pipeline_state(target, phase_key, "done" if success else "failed")
                phase_results.append({
                    "phase": phase_key, "label": phase_label,
                    "success": success, "elapsed": elapsed,
                })
                progress.advance(master)

        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️  Pipeline interrupted by user.[/yellow]")
            console.print("   Use [cyan]--resume[/cyan] to continue from where you left off.")

    total_elapsed = time.time() - total_start

    # ── Summary table ──
    summary = Table(title="Pipeline Summary", box=box.ROUNDED)
    summary.add_column("#", style="dim", width=3)
    summary.add_column("Phase", style="cyan")
    summary.add_column("Status", justify="center")
    summary.add_column("Duration", justify="right", style="yellow")
    for i, r in enumerate(phase_results, 1):
        st = "[green]✓[/green]" if r["success"] else "[red]✗[/red]"
        summary.add_row(str(i), r["label"], st, f"{r['elapsed']:.0f}s")
    summary.add_section()
    summary.add_row("", "[bold]TOTAL[/bold]", "", f"[bold]{total_elapsed:.0f}s ({total_elapsed/60:.1f}m)[/bold]")
    console.print(summary)

    # Show output locations
    from config import TARGET_DIR, TARGET_LLM_DIR, TARGET_REPORT_DIR
    console.print(Panel.fit(
        f"📁 Recon data:    [cyan]{TARGET_DIR}[/cyan]\n"
        f"🤖 LLM analysis: [cyan]{TARGET_LLM_DIR}[/cyan]\n"
        f"📝 Reports:      [cyan]{TARGET_REPORT_DIR}[/cyan]",
        title="[green bold]✅ Pipeline Complete[/green bold]",
        style="green",
    ))


if __name__ == "__main__":
    main()

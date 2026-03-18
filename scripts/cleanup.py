#!/usr/bin/env python3
"""
BBHunter - Cleanup Script
===========================
Wipes generated data so you can move to a new target with a clean slate.
Shows a ⏳ progress bar with estimated time remaining.

Modes:
    --target doordash.com   Only wipe data for that specific target
    --all                   Wipe ALL targets' data
    --keep-db               Keep the SQLite DB (just clear target rows)
    --dry-run               Show what would be deleted without deleting

Usage:
    python3 scripts/cleanup.py                           # interactive prompt
    python3 scripts/cleanup.py --target doordash.com     # wipe doordash only
    python3 scripts/cleanup.py --all                     # wipe everything
    python3 scripts/cleanup.py --all --dry-run           # preview only
"""

import argparse
import logging
import os
import shutil
import sqlite3
import sys
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
from rich.prompt import Confirm, Prompt

console = Console()

# ── Paths ─────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
LLM_DIR = BASE_DIR / "llm_analysis"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
DB_PATH = DATA_DIR / "bbhunter.db"
MODELS_DIR = DATA_DIR / "models"
PIPELINE_STATE = DATA_DIR / "pipeline_state.json"


def sizeof_fmt(num: float) -> str:
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(num) < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def dir_size(path: Path) -> int:
    """Total size of a directory in bytes."""
    if not path.exists():
        return 0
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


def file_count(path: Path) -> int:
    """Count files in a directory recursively."""
    if not path.exists():
        return 0
    return sum(1 for f in path.rglob("*") if f.is_file())


def domain_to_dir(domain: str) -> str:
    """Convert domain to directory name (dots → underscores)."""
    return domain.replace(".", "_")


def list_targets() -> list[str]:
    """Discover all target directories across data/llm_analysis/reports."""
    targets = set()
    for base in [DATA_DIR, LLM_DIR, REPORTS_DIR]:
        if base.exists():
            for d in base.iterdir():
                if d.is_dir() and d.name not in ("models", "__pycache__"):
                    # Convert back: doordash_com → doordash.com (best guess)
                    targets.add(d.name)
    return sorted(targets)


def get_target_dirs(target_dir_name: str) -> list[tuple[str, Path]]:
    """Get all directories associated with a target."""
    dirs = []
    for label, base in [("data", DATA_DIR), ("llm_analysis", LLM_DIR), ("reports", REPORTS_DIR)]:
        d = base / target_dir_name
        if d.exists():
            dirs.append((label, d))
    return dirs


def preview_target(target_dir_name: str):
    """Show what would be cleaned for a target."""
    dirs = get_target_dirs(target_dir_name)
    if not dirs:
        print(f"  (no data found for {target_dir_name})")
        return

    total_size = 0
    total_files = 0
    for label, d in dirs:
        size = dir_size(d)
        count = file_count(d)
        total_size += size
        total_files += count
        print(f"  {label + '/':<16} {d.name + '/':<25} {count:>4} files  {sizeof_fmt(size):>10}")

    print(f"  {'':16} {'TOTAL':<25} {total_files:>4} files  {sizeof_fmt(total_size):>10}")


def _collect_items(target_dir_name: str | None = None, keep_db: bool = False) -> list[dict]:
    """
    Build a flat list of cleanup items.
    Each: {"desc": str, "type": "dir"|"file"|"db", "path": Path, "size": int, ...}
    """
    items: list[dict] = []

    if target_dir_name:
        # ── Single-target dirs ──
        for label, d in get_target_dirs(target_dir_name):
            items.append({
                "desc": f"{label}/{d.name}",
                "type": "dir",
                "path": d,
                "size": dir_size(d),
            })
        # ── DB rows ──
        if DB_PATH.exists() and not keep_db:
            domain_guess = target_dir_name.replace("_", ".")
            items.append({
                "desc": f"DB records for {domain_guess}",
                "type": "db_target",
                "domain": domain_guess,
                "path": DB_PATH,
                "size": 0,
            })
    else:
        # ── All target dirs ──
        for t in list_targets():
            for label, d in get_target_dirs(t):
                items.append({
                    "desc": f"{label}/{d.name}",
                    "type": "dir",
                    "path": d,
                    "size": dir_size(d),
                })

        # ── Logs ──
        if LOGS_DIR.exists():
            for f in LOGS_DIR.glob("*"):
                if f.is_file() and f.stat().st_size > 0:
                    items.append({
                        "desc": f"logs/{f.name}",
                        "type": "file",
                        "path": f,
                        "size": f.stat().st_size,
                    })

        # ── Pipeline state ──
        if PIPELINE_STATE.exists():
            items.append({
                "desc": "pipeline_state.json",
                "type": "file",
                "path": PIPELINE_STATE,
                "size": PIPELINE_STATE.stat().st_size,
            })

        # ── Learning models ──
        if MODELS_DIR.exists() and file_count(MODELS_DIR) > 0:
            items.append({
                "desc": "data/models (learning data)",
                "type": "dir",
                "path": MODELS_DIR,
                "size": dir_size(MODELS_DIR),
            })

        # ── DB (full wipe) ──
        if DB_PATH.exists() and not keep_db:
            items.append({
                "desc": f"bbhunter.db ({sizeof_fmt(DB_PATH.stat().st_size)})",
                "type": "file",
                "path": DB_PATH,
                "size": DB_PATH.stat().st_size,
            })

        # ── Stray reports ──
        if REPORTS_DIR.exists():
            for f in REPORTS_DIR.glob("*.md"):
                items.append({"desc": f"reports/{f.name}", "type": "file", "path": f, "size": f.stat().st_size})
            for f in REPORTS_DIR.glob("*.json"):
                items.append({"desc": f"reports/{f.name}", "type": "file", "path": f, "size": f.stat().st_size})

    return items


def _show_preview_table(items: list[dict]):
    """Show a Rich table of items that will be deleted."""
    table = Table(title="Items to Delete", show_lines=False, title_style="bold red")
    table.add_column("#", style="dim", width=3)
    table.add_column("Item", style="cyan")
    table.add_column("Type", style="dim")
    table.add_column("Size", justify="right", style="yellow")

    total_size = 0
    for i, item in enumerate(items, 1):
        icon = {"dir": "📁", "file": "📄", "db_target": "🗄️ "}.get(item["type"], "❓")
        table.add_row(str(i), f"{icon}  {item['desc']}", item["type"], sizeof_fmt(item["size"]))
        total_size += item["size"]

    table.add_section()
    table.add_row("", "[bold]TOTAL[/bold]", f"{len(items)} items", f"[bold]{sizeof_fmt(total_size)}[/bold]")
    console.print(table)


def _execute_items(items: list[dict], dry_run: bool = False):
    """Run cleanup with a Rich progress bar + ETA."""
    if not items:
        console.print("[green]✓ Nothing to clean![/green]")
        return

    label = "[yellow]DRY RUN[/yellow]  " if dry_run else ""

    with Progress(
        SpinnerColumn(),
        TextColumn(f"{label}" + "[bold blue]{task.description}[/bold blue]"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•  ETA"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:

        task = progress.add_task("Starting cleanup…", total=len(items))

        for item in items:
            progress.update(task, description=item["desc"])

            if not dry_run:
                try:
                    if item["type"] == "dir":
                        shutil.rmtree(item["path"])
                    elif item["type"] == "file":
                        item["path"].unlink()
                    elif item["type"] == "db_target":
                        _clean_db_target(item["domain"], dry_run=False, quiet=True)
                except Exception as e:
                    console.print(f"  [red]✗ {item['desc']}: {e}[/red]")

            # Small pause so the ETA and bar are visible even for fast ops
            time.sleep(0.18)
            progress.advance(task)

    total_size = sum(i["size"] for i in items)
    if dry_run:
        console.print(f"\n[yellow]Would delete {len(items)} items ({sizeof_fmt(total_size)})[/yellow]")
    else:
        console.print(f"\n[green]✓ Deleted {len(items)} items ({sizeof_fmt(total_size)})[/green]")


def clean_target(target_dir_name: str, dry_run: bool = False, keep_db: bool = False):
    """Remove all data for a specific target — with progress bar."""
    items = _collect_items(target_dir_name, keep_db=keep_db)
    if not items:
        console.print(f"[green]✓ No data found for {target_dir_name}[/green]")
        return
    _show_preview_table(items)
    console.print()
    _execute_items(items, dry_run=dry_run)


def _clean_db_target(domain: str, dry_run: bool = False, quiet: bool = False):
    """Remove all DB rows for a target domain."""
    if not DB_PATH.exists():
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    # Find target ID
    row = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
    if not row:
        # Try with underscores
        row = conn.execute("SELECT id FROM targets WHERE domain LIKE ?",
                           (f"%{domain.split('.')[0]}%",)).fetchone()
    if not row:
        if not quiet:
            console.print(f"  [dim](no DB records found for {domain})[/dim]")
        conn.close()
        return

    target_id = row["id"]

    # Count rows in each table
    tables = [
        ("assets", "target_id"),
        ("endpoints", "target_id"),
        ("parameters", "target_id"),
        ("dns_records", "target_id"),
        ("technologies", "target_id"),
        ("vulnerabilities", "target_id"),
        ("llm_chunks", "target_id"),
        ("llm_analyses", "target_id"),
        ("scan_runs", "target_id"),
        ("action_log", "scan_run_id"),  # handled separately
    ]

    total_rows = 0
    for table, col in tables:
        try:
            if table == "action_log":
                count = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {col} IN "
                    f"(SELECT id FROM scan_runs WHERE target_id = ?)",
                    (target_id,)
                ).fetchone()[0]
            else:
                count = conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE {col} = ?",
                    (target_id,)
                ).fetchone()[0]
            if count > 0:
                total_rows += count
                if dry_run and not quiet:
                    console.print(f"  [yellow]Would delete {count} rows from {table}[/yellow]")
                else:
                    if table == "action_log":
                        conn.execute(
                            f"DELETE FROM {table} WHERE {col} IN "
                            f"(SELECT id FROM scan_runs WHERE target_id = ?)",
                            (target_id,)
                        )
                    else:
                        conn.execute(
                            f"DELETE FROM {table} WHERE {col} = ?",
                            (target_id,)
                        )
        except Exception as exc:
            logging.debug(f"Failed to delete from table {table}: {exc}")

    # Delete the target itself
    if not dry_run:
        conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        conn.commit()
        # Compact the database
        conn.execute("VACUUM")
        if not quiet:
            console.print(f"  [green]✓ Removed {total_rows} DB rows + target record for {domain}[/green]")
    else:
        if not quiet:
            console.print(f"  [yellow]Would delete {total_rows} DB rows + target record for {domain}[/yellow]")

    conn.close()


def clean_all(dry_run: bool = False, keep_db: bool = False):
    """Remove ALL generated data — with progress bar."""
    items = _collect_items(target_dir_name=None, keep_db=keep_db)
    if not items:
        console.print("[green]✓ Workspace already clean![/green]")
        return
    _show_preview_table(items)
    console.print()
    _execute_items(items, dry_run=dry_run)


def _next_steps_panel():
    """Show a helpful 'what next' panel after cleanup."""
    console.print()
    console.print(Panel.fit(
        "[green bold]✅  Cleanup complete![/green bold]\n\n"
        "To start on a new target:\n"
        "  [cyan]export BB_TARGET=newtarget.com[/cyan]\n"
        "  [cyan]python3 scripts/run_pipeline.py --target newtarget.com --phase all[/cyan]",
        title="Next Steps",
        style="green",
    ))


def interactive_mode():
    """Interactive target selection with Rich UI."""
    targets = list_targets()

    if not targets:
        console.print("[green]✓ No target data found. Workspace is clean![/green]")
        return

    console.print()
    console.print(Panel.fit(
        "[bold]🧹 BBHunter Cleanup[/bold]\n"
        "Select a target to clean up, or clean everything.",
        style="blue",
    ))

    # Build a table of discovered targets
    table = Table(title="Discovered Targets", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Directory", style="cyan bold")
    table.add_column("Files", justify="right")
    table.add_column("Size", justify="right", style="yellow")

    total_files = 0
    total_size = 0
    for i, t in enumerate(targets, 1):
        t_dirs = get_target_dirs(t)
        t_files = sum(file_count(d) for _, d in t_dirs)
        t_size = sum(dir_size(d) for _, d in t_dirs)
        total_files += t_files
        total_size += t_size
        table.add_row(str(i), t, str(t_files), sizeof_fmt(t_size))

    if DB_PATH.exists():
        total_size += DB_PATH.stat().st_size
    table.add_section()
    table.add_row("A", "[red bold]ALL TARGETS[/red bold]", str(total_files), sizeof_fmt(total_size), style="red")

    console.print(table)
    console.print()

    choice = Prompt.ask(
        "Select target [number / A for all / Q to quit]",
        default="Q",
    )

    if choice.upper() == "Q":
        console.print("[dim]Cancelled.[/dim]")
        return
    elif choice.upper() == "A":
        target_dir = None
        label = "ALL targets"
    else:
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(targets):
                target_dir = targets[idx]
                label = target_dir
            else:
                console.print("[red]Invalid selection.[/red]")
                return
        except ValueError:
            console.print("[red]Invalid selection.[/red]")
            return

    keep_db = not Confirm.ask(f"Also clean DB records for {label}?", default=True)

    if target_dir:
        items = _collect_items(target_dir, keep_db=keep_db)
    else:
        items = _collect_items(None, keep_db=keep_db)

    if not items:
        console.print("[green]✓ Nothing to clean![/green]")
        return

    _show_preview_table(items)
    console.print()

    if Confirm.ask("[bold red]Proceed with cleanup?[/bold red]", default=False):
        _execute_items(items)
        _next_steps_panel()
    else:
        console.print("[dim]Cancelled.[/dim]")


def main():
    parser = argparse.ArgumentParser(
        description="BBHunter - Clean up generated data before switching targets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/cleanup.py                              # interactive mode
  python3 scripts/cleanup.py --target doordash.com        # clean one target
  python3 scripts/cleanup.py --all                        # clean everything
  python3 scripts/cleanup.py --all --dry-run              # preview only
  python3 scripts/cleanup.py --all --keep-db              # keep DB, remove files
  python3 scripts/cleanup.py --list                       # list targets with data
  python3 scripts/cleanup.py --all --yes                  # skip confirmation
        """,
    )
    parser.add_argument("--target", "-t", type=str, help="Clean data for a specific target domain")
    parser.add_argument("--all", "-a", action="store_true", help="Clean ALL target data")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Preview what would be deleted")
    parser.add_argument("--keep-db", action="store_true", help="Keep the SQLite database")
    parser.add_argument("--list", "-l", action="store_true", help="List targets that have data")
    parser.add_argument("--yes", "-y", action="store_true", help="Skip confirmation prompts")
    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold blue]🧹 BBHunter Cleanup Tool[/bold blue]",
        subtitle="Clean generated data before switching targets",
    ))

    # ── List mode ──
    if args.list:
        targets = list_targets()
        if not targets:
            console.print("[dim]No target data found.[/dim]")
        else:
            console.print(f"\n[bold]Targets with data ({len(targets)}):[/bold]\n")
            for t in targets:
                preview_target(t)
                console.print()
        return

    # ── Single target ──
    if args.target:
        dir_name = domain_to_dir(args.target)
        console.print(f"\n[bold]Target:[/bold] {args.target}  →  [cyan]{dir_name}/[/cyan]\n")
        items = _collect_items(dir_name, keep_db=args.keep_db)
        if not items:
            console.print("[green]✓ No data found for this target.[/green]")
            return
        _show_preview_table(items)
        console.print()
        if args.dry_run:
            _execute_items(items, dry_run=True)
            return
        if not args.yes:
            if not Confirm.ask("[bold red]Delete all listed items?[/bold red]", default=False):
                console.print("[dim]Cancelled.[/dim]")
                return
        _execute_items(items)
        _next_steps_panel()
        return

    # ── All targets ──
    if args.all:
        items = _collect_items(None, keep_db=args.keep_db)
        if not items:
            console.print("[green]✓ Workspace already clean![/green]")
            return
        _show_preview_table(items)
        console.print()
        if args.dry_run:
            _execute_items(items, dry_run=True)
            return
        if not args.yes:
            if not Confirm.ask("[bold red]Delete EVERYTHING?[/bold red]", default=False):
                console.print("[dim]Cancelled.[/dim]")
                return
        _execute_items(items)
        _next_steps_panel()
        return

    # ── Default: interactive ──
    interactive_mode()


if __name__ == "__main__":
    main()
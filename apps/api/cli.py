"""Bug Bounty Platform CLI.

Usage:
    bbp program create --name "My Program" --org "my-org"
    bbp scope add --program my-program --domain example.com
    bbp scan start --program my-program --target https://example.com
    bbp scan status --scan-id <id>
    bbp agents list
    bbp findings list
    bbp finding validate --finding-id <id>
    bbp regression run --finding-id <id>
    bbp report generate --scan-id <id>
"""
from __future__ import annotations

import json
import sys

import click
import httpx

API_BASE = "http://localhost:8000/api/v1"


@click.group()
def cli():
    """Bug Bounty Platform CLI."""
    pass


@cli.group()
def program():
    """Program management."""
    pass


@program.command("create")
@click.option("--name", required=True)
@click.option("--org-id", required=True)
@click.option("--domain", multiple=True)
def program_create(name: str, org_id: str, domain: tuple):
    scope = {"domains": list(domain), "protocols": ["https"]} if domain else {}
    resp = httpx.post(f"{API_BASE}/programs", json={
        "name": name,
        "organization_id": org_id,
        "scope": scope,
    })
    click.echo(json.dumps(resp.json(), indent=2))


@cli.group()
def scan():
    """Scan management."""
    pass


@scan.command("start")
@click.option("--program-id", required=True)
@click.option("--target", required=True)
def scan_start(program_id: str, target: str):
    resp = httpx.post(f"{API_BASE}/scans", json={
        "program_id": program_id,
        "target": target,
    })
    if resp.status_code == 403:
        click.echo(f"ERROR: Target rejected – {resp.json().get('detail', 'not in scope')}", err=True)
        sys.exit(1)
    click.echo(json.dumps(resp.json(), indent=2))


@scan.command("status")
@click.option("--scan-id", required=True)
def scan_status(scan_id: str):
    resp = httpx.get(f"{API_BASE}/scans/{scan_id}")
    click.echo(json.dumps(resp.json(), indent=2))


@cli.group()
def agents():
    """Agent management."""
    pass


@agents.command("list")
def agents_list():
    resp = httpx.get(f"{API_BASE}/agents/types")
    click.echo(json.dumps(resp.json(), indent=2))


@cli.group()
def findings():
    """Finding management."""
    pass


@findings.command("list")
def findings_list():
    resp = httpx.get(f"{API_BASE}/findings")
    click.echo(json.dumps(resp.json(), indent=2))


@cli.group()
def finding():
    """Single finding operations."""
    pass


@finding.command("validate")
@click.option("--finding-id", required=True)
def finding_validate(finding_id: str):
    resp = httpx.post(f"{API_BASE}/findings/{finding_id}/validate")
    click.echo(json.dumps(resp.json(), indent=2))


@cli.group()
def regression():
    """Regression testing."""
    pass


@regression.command("run")
@click.option("--finding-id", required=True)
def regression_run(finding_id: str):
    resp = httpx.post(f"{API_BASE}/findings/{finding_id}/regression")
    click.echo(json.dumps(resp.json(), indent=2))


@cli.group()
def report():
    """Report management."""
    pass


@report.command("generate")
@click.option("--scan-id", required=True)
def report_generate(scan_id: str):
    resp = httpx.post(f"{API_BASE}/reports", params={"scan_id": scan_id})
    click.echo(json.dumps(resp.json(), indent=2))


def main():
    cli()


if __name__ == "__main__":
    main()

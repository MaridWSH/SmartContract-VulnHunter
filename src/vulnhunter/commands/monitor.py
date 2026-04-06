"""Vaulthunter 24/7 monitor command."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from vulnhunter.monitor import VaulthunterMonitor, MonitoredTarget, get_monitor

app = typer.Typer(help="🏹 Vaulthunter 24/7 continuous monitoring")
console = Console()

_monitor_task: Optional[asyncio.Task] = None


@app.command()
def start(
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Run as background daemon"),
):
    """Start Vaulthunter 24/7 monitoring."""
    console.print("[bold green]🏹 Starting Vaulthunter 24/7 Monitor...[/bold green]")

    monitor = get_monitor()

    # Add console alert handler
    def console_alert(alert):
        console.print("\n[bold red]🚨 SECURITY ALERT[/bold red]")
        console.print(f"Target: {alert['target']}")
        console.print(f"New findings: {alert['new_findings']}")
        console.print(f"Severity breakdown: {alert['severity_breakdown']}")

    monitor.on_alert(console_alert)

    try:
        if daemon:
            # Run in background (simplified - would need proper daemonization)
            console.print("[dim]Running in daemon mode...[/dim]")

        asyncio.run(monitor.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping monitor...[/yellow]")
        asyncio.run(monitor.stop())


@app.command()
def stop():
    """Stop Vaulthunter monitoring."""
    console.print("[yellow]Stopping Vaulthunter...[/yellow]")
    monitor = get_monitor()
    asyncio.run(monitor.stop())
    console.print("[green]✓ Monitor stopped[/green]")


@app.command()
def add(
    name: str = typer.Argument(..., help="Target name"),
    path: str = typer.Argument(..., help="Path to contract/directory"),
    interval: int = typer.Option(3600, "--interval", "-i", help="Scan interval in seconds"),
    threshold: str = typer.Option(
        "MEDIUM", "--threshold", "-t", help="Alert threshold (CRITICAL/HIGH/MEDIUM/LOW)"
    ),
    webhook: Optional[str] = typer.Option(None, "--webhook", "-w", help="Webhook URL for alerts"),
):
    """Add a target to monitor."""
    monitor = get_monitor()

    target = MonitoredTarget(
        id=f"{name.lower().replace(' ', '_')}_{hash(path) % 10000}",
        name=name,
        target_type="directory",  # Auto-detect would be better
        path=path,
        scan_interval=interval,
        alert_threshold=threshold,
        webhook_url=webhook,
    )

    target_id = monitor.add_target(target)
    console.print(f"[green]✓ Added target '{name}' (ID: {target_id})[/green]")
    console.print(f"  Path: {path}")
    console.print(f"  Interval: {interval}s")
    console.print(f"  Threshold: {threshold}")


@app.command()
def remove(
    target_id: str = typer.Argument(..., help="Target ID to remove"),
):
    """Remove a monitored target."""
    monitor = get_monitor()

    if monitor.remove_target(target_id):
        console.print(f"[green]✓ Removed target {target_id}[/green]")
    else:
        console.print(f"[red]✗ Target {target_id} not found[/red]")
        raise typer.Exit(1)


@app.command()
def list():
    """List all monitored targets."""
    monitor = get_monitor()
    targets = monitor.list_targets()

    if not targets:
        console.print("[dim]No targets being monitored[/dim]")
        return

    table = Table(title="Monitored Targets")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("Path", style="white")
    table.add_column("Interval", justify="right")
    table.add_column("Last Scan", style="dim")
    table.add_column("Findings", justify="right")
    table.add_column("Active", justify="center")

    for t in targets:
        last_scan = t.last_scan.strftime("%Y-%m-%d %H:%M") if t.last_scan else "Never"
        status = "✓" if t.is_active else "✗"
        table.add_row(
            t.id[:20] + "..." if len(t.id) > 20 else t.id,
            t.name,
            t.path[:40] + "..." if len(t.path) > 40 else t.path,
            f"{t.scan_interval}s",
            last_scan,
            str(t.last_findings_count),
            status,
        )

    console.print(table)


@app.command()
def status():
    """Show Vaulthunter status."""
    monitor = get_monitor()
    targets = monitor.list_targets()

    console.print("[bold blue]🏹 Vaulthunter Status[/bold blue]")
    console.print(f"Monitored targets: {len(targets)}")
    console.print(f"Active targets: {sum(1 for t in targets if t.is_active)}")
    console.print(f"Total findings tracked: {sum(t.last_findings_count for t in targets)}")

"""SmartContract VulnHunter - Main entry point."""

from __future__ import annotations

import typer
from rich.console import Console

from vulnhunter.commands import (
    scan,
    report,
    config,
    bounty,
    clone,
    recon,
    analyze,
    poc,
    hunt,
    audit,
)
from vulnhunter.config import get_config

app = typer.Typer(
    name="vulnhunter",
    help="🔍 Ultimate smart contract security CLI framework for bug bounty researchers",
    rich_markup_mode="rich",
    add_completion=False,
)

console = Console()

# Add subcommands
app.add_typer(scan.app, name="scan", help="🔍 Scan targets for vulnerabilities")
app.add_typer(clone.app, name="clone", help="📥 Clone repositories for analysis")
app.add_typer(recon.app, name="recon", help="🗺️  Reconnaissance and target analysis")
app.add_typer(analyze.app, name="analyze", help="🧠 Deep LLM analysis")
app.add_typer(poc.app, name="poc", help="🎯 PoC exploit generation")
app.add_typer(hunt.app, name="hunt", help="🏹 Automated vulnerability hunting")
app.add_typer(audit.app, name="audit", help="🔬 Interactive end-to-end audit workflow")
app.add_typer(report.app, name="report", help="📊 Generate platform-specific reports")
app.add_typer(config.app, name="config", help="⚙️  Manage configuration")
app.add_typer(bounty.app, name="bounty", help="💰 Prepare bounty submissions")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output"),
    config_path: str = typer.Option(None, "--config", "-c", help="Path to config file"),
) -> None:
    """SmartContract VulnHunter - Smart contract security framework for bug bounty researchers.

    Orchestrates 15+ security scanners, LLM analysis, PoC generation, and
    platform-specific reporting across Solidity, Rust/Solana, Vyper, and Cairo.
    """
    if verbose:
        console.print("[dim]Verbose mode enabled[/dim]")
    if config_path:
        # Config will be loaded from specified path
        pass


if __name__ == "__main__":
    app()

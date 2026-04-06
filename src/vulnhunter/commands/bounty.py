"""Bounty command for SmartContract VulnHunter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vulnhunter.reporters.immunefi import ImmunefiReporter
from vulnhunter.reporters.code4rena import Code4renaReporter
from vulnhunter.reporters.sherlock import SherlockReporter
from vulnhunter.reporters.codehawks import CodehawksReporter

app = typer.Typer(help="💰 Prepare bounty submissions")
console = Console()

REPORTERS = {
    "immunefi": ImmunefiReporter,
    "code4rena": Code4renaReporter,
    "sherlock": SherlockReporter,
    "codehawks": CodehawksReporter,
}


@app.command()
def prepare(
    findings_file: Path = typer.Argument(..., help="Findings JSON/SARIF file"),
    platform: str = typer.Option(
        ...,
        "--platform",
        "-p",
        help="Target platform: immunefi, code4rena, sherlock, codehawks",
    ),
    output: Path = typer.Option(
        Path("./bounty-submission.md"), "--output", "-o", help="Output file"
    ),
    poc: Optional[Path] = typer.Option(None, "--poc", help="Path to PoC file"),
) -> None:
    """Prepare submission-ready bounty report."""
    console.print(f"[bold blue]💰 Preparing {platform} bounty submission...[/bold blue]")

    # Validate platform
    valid_platforms = list(REPORTERS.keys())
    if platform not in valid_platforms:
        console.print(
            f"[bold red]✗ Invalid platform. Choose from: {', '.join(valid_platforms)}[/bold red]"
        )
        raise typer.Exit(1)

    # Load findings
    if not findings_file.exists():
        console.print(f"[bold red]✗ Findings file not found: {findings_file}[/bold red]")
        raise typer.Exit(1)

    try:
        with open(findings_file) as f:
            findings = json.load(f)

        # Load PoC if provided
        poc_content = None
        if poc and poc.exists():
            poc_content = poc.read_text()
            console.print(f"[dim]📎 Including PoC: {poc}[/dim]")

        # Generate platform-specific report
        reporter_class = REPORTERS[platform]
        reporter = reporter_class()
        report = reporter.generate(findings, poc=poc_content)

        # Write output
        output.write_text(report)
        console.print(f"[bold green]✓ Bounty submission ready: {output}[/bold green]")
        console.print("[dim]Remember to review and validate the PoC before submitting![/dim]")
    except Exception as e:
        console.print(f"[bold red]✗ Bounty preparation failed: {e}[/bold red]")
        raise typer.Exit(1)

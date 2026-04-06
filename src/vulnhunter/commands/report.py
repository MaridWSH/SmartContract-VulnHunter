"""Report command for SmartContract VulnHunter."""

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

app = typer.Typer(help="📊 Generate platform-specific reports")
console = Console()

REPORTERS = {
    "immunefi": ImmunefiReporter,
    "code4rena": Code4renaReporter,
    "sherlock": SherlockReporter,
    "codehawks": CodehawksReporter,
}


@app.command()
def generate(
    input_dir: Path = typer.Argument(..., help="Results directory"),
    platform: str = typer.Option(
        "immunefi",
        "--platform",
        "-p",
        help="Platform: immunefi, code4rena, sherlock, codehawks",
    ),
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Output format: markdown, pdf, json"
    ),
    output: Path = typer.Option(Path("./report.md"), "--output", "-o", help="Output file"),
) -> None:
    """Generate platform-specific vulnerability report."""
    console.print(f"[bold blue]📊 Generating {platform} report...[/bold blue]")

    # Validate platform
    valid_platforms = list(REPORTERS.keys())
    if platform not in valid_platforms:
        console.print(
            f"[bold red]✗ Invalid platform. Choose from: {', '.join(valid_platforms)}[/bold red]"
        )
        raise typer.Exit(1)

    # Load findings
    findings_file = input_dir / "findings.json"
    if not findings_file.exists():
        console.print(f"[bold red]✗ Findings file not found: {findings_file}[/bold red]")
        raise typer.Exit(1)

    try:
        with open(findings_file) as f:
            findings = json.load(f)

        # Generate report
        reporter_class = REPORTERS[platform]
        reporter = reporter_class()
        report = reporter.generate(findings)

        # Write output
        output.write_text(report)
        console.print(f"[bold green]✓ Report generated: {output}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]✗ Report generation failed: {e}[/bold red]")
        raise typer.Exit(1)

"""Scan command for SmartContract VulnHunter."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnhunter.core.orchestrator import Orchestrator
from vulnhunter.core.sarif_merger import SarifMerger
from vulnhunter.core.deduplicator import Deduplicator
from vulnhunter.config import get_config

app = typer.Typer(help="🔍 Scan targets for vulnerabilities")
console = Console()


@app.command()
def run(
    target: str = typer.Argument(..., help="Target directory or file to scan"),
    tools: Optional[List[str]] = typer.Option(
        None, "--tools", "-t", help="Tools to run (default: all available)"
    ),
    output: Path = typer.Option(
        Path("./vulnhunter-results"), "--output", "-o", help="Output directory"
    ),
    parallel: int = typer.Option(5, "--parallel", "-p", help="Max parallel tasks"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout per tool (seconds)"),
) -> None:
    """Run security scan on a target."""
    console.print(f"[bold blue]🔍 Scanning {target}...[/bold blue]")

    # Ensure output directory exists
    output.mkdir(parents=True, exist_ok=True)

    # Load config
    config = get_config()

    # Initialize orchestrator
    orchestrator = Orchestrator(max_concurrent=parallel, config=config)
    merger = SarifMerger()
    deduplicator = Deduplicator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running scanners...", total=None)

        # Run scan
        try:
            # Import mock scanner for testing
            from vulnhunter.adapters.mock_scanner_adapter import MockScannerAdapter

            # Create adapter and run scan
            adapter = MockScannerAdapter()
            results = asyncio.run(adapter.run(target))

            # Merge and deduplicate findings
            merged = merger.merge_findings([results])
            unique = deduplicator.deduplicate(merged)

            # Save results
            findings_file = output / "findings.json"
            with open(findings_file, "w") as f:
                json.dump([f.dict() if hasattr(f, "dict") else f for f in unique], f, indent=2)

            progress.update(task, completed=True)
            console.print(
                f"[bold green]✓ Scan complete. {len(unique)} unique findings saved to {output}[/bold green]"
            )
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[bold red]✗ Scan failed: {e}[/bold red]")
            raise typer.Exit(1)

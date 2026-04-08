"""Scan command for VulnHunter."""

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
from vulnhunter.core.task import Task, TaskStatus
from vulnhunter.config import get_config
from vulnhunter.adapters.slither_adapter import SlitherAdapter
from vulnhunter.adapters.aderyn_adapter import AderynAdapter
from vulnhunter.adapters.semgrep_adapter import SemgrepAdapter
from vulnhunter.adapters.solhint_adapter import SolhintAdapter
from vulnhunter.adapters.mythril_adapter import MythrilAdapter

app = typer.Typer(help="🔍 Scan targets for vulnerabilities")
console = Console()


def get_available_adapters(target: str, tools: Optional[List[str]] = None) -> List:
    """Get list of available adapters for the target."""
    all_adapters = [
        ("slither", SlitherAdapter()),
        ("aderyn", AderynAdapter()),
        ("semgrep", SemgrepAdapter()),
        ("solhint", SolhintAdapter()),
        ("mythril", MythrilAdapter()),
    ]

    available = []
    for name, adapter in all_adapters:
        if tools and name not in tools:
            continue
        if adapter.is_available():
            available.append((name, adapter))
            console.print(f"[dim]✓ {name} adapter available[/dim]")
        else:
            console.print(f"[dim yellow]⚠ {name} not available[/dim yellow]")

    return available


@app.command()
def run(
    target: str = typer.Argument(..., help="Target directory or file to scan"),
    tools: Optional[str] = typer.Option(
        None, "--tools", "-t", help="Tools to run (comma-separated, default: all available)"
    ),
    output: Path = typer.Option(
        Path("./vulnhunter-results"), "--output", "-o", help="Output directory"
    ),
    parallel: int = typer.Option(5, "--parallel", "-p", help="Max parallel tasks"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout per tool (seconds)"),
    enrich: bool = typer.Option(
        True, "--enrich/--no-enrich", help="Enrich findings with Solodit KB"
    ),
) -> None:
    """Run security scan on a target using real security scanners."""
    console.print(f"[bold blue]🔍 VulnHunter Scan[/bold blue]")
    console.print(f"[dim]Target: {target}[/dim]")
    console.print()

    # Ensure output directory exists
    output.mkdir(parents=True, exist_ok=True)

    # Load config
    config = get_config()

    # Parse tools list
    tool_list = None
    if tools:
        tool_list = [t.strip() for t in tools.split(",")]

    # Get available adapters
    available_adapters = get_available_adapters(target, tool_list)

    if not available_adapters:
        console.print(
            "[bold red]✗ No scanners available. Please install at least one scanner:[/bold red]"
        )
        console.print("  - pip install slither-analyzer")
        console.print("  - cargo install aderyn")
        console.print("  - pip install semgrep")
        raise typer.Exit(1)

    # Initialize orchestrator
    orchestrator = Orchestrator(max_concurrent=parallel, config=config)
    merger = SarifMerger()
    deduplicator = Deduplicator()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Running {len(available_adapters)} scanners...", total=None)

        # Run scan
        try:
            # Create tasks for each adapter
            tasks = [
                Task(tool=name, target=target, timeout_seconds=timeout)
                for name, _ in available_adapters
            ]

            # Create adapter dictionary
            adapters = {name: adapter for name, adapter in available_adapters}

            # Run all scanners in parallel
            results = asyncio.run(orchestrator.run_parallel(tasks, adapters))

            # Collect findings from all successful tasks
            all_findings = []
            for task_result in results:
                if task_result.status == TaskStatus.COMPLETED and task_result.result:
                    if isinstance(task_result.result, list):
                        all_findings.extend(task_result.result)
                    else:
                        all_findings.append(task_result.result)

            # Merge and deduplicate findings
            merged = merger.merge_findings([all_findings])
            unique = deduplicator.deduplicate(merged)

            # Enrich with Solodit KB if enabled
            if enrich:
                progress.update(task, description="Enriching with Solodit KB...")
                try:
                    from vulnhunter.solodit.enricher import SoloditEnricher

                    enricher = SoloditEnricher()
                    unique = asyncio.run(enricher.enrich_findings(unique))
                    console.print(f"[dim]✓ Enriched with Solodit KB[/dim]")
                except Exception as e:
                    console.print(f"[dim yellow]⚠ Solodit enrichment skipped: {e}[/dim yellow]")

            # Save results
            findings_file = output / "findings.json"
            with open(findings_file, "w") as f:
                json.dump(
                    [f.dict() if hasattr(f, "dict") else f for f in unique],
                    f,
                    indent=2,
                    default=str,
                )

            progress.update(task, completed=True)
            console.print()
            console.print(
                f"[bold green]✓ Scan complete. {len(unique)} unique findings saved to {findings_file}[/bold green]"
            )

            # Print summary
            severity_counts = {}
            for finding in unique:
                sev = getattr(finding, "severity", "UNKNOWN")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            if severity_counts:
                console.print("\n[bold]Findings by severity:[/bold]")
                for sev, count in sorted(
                    severity_counts.items(),
                    key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                        x[0], 5
                    ),
                ):
                    color = {
                        "CRITICAL": "red",
                        "HIGH": "red",
                        "MEDIUM": "yellow",
                        "LOW": "green",
                        "INFO": "blue",
                    }.get(sev, "white")
                    console.print(f"  [{color}]{sev}[/{color}]: {count}")

        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"[bold red]✗ Scan failed: {e}[/bold red]")
            import traceback

            console.print(f"[dim red]{traceback.format_exc()}[/dim red]")
            raise typer.Exit(1)

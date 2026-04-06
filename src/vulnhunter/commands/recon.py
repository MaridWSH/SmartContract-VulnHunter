"""Recon command for SmartContract VulnHunter."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.syntax import Syntax

from vulnhunter.recon.engine import ReconEngine
from vulnhunter.recon.models.recon_report import ReconReport

app = typer.Typer(help="🔍 Reconnaissance - gather intelligence before scanning")
console = Console()


@app.command()
def run(
    target: str = typer.Argument(..., help="Path to target codebase"),
    output: Path = typer.Option(
        Path("./recon-report.json"), "--output", "-o", help="Output file for recon report (JSON)"
    ),
    markdown: Optional[Path] = typer.Option(
        None, "--markdown", "-m", help="Also generate Markdown report"
    ),
    phases: Optional[str] = typer.Option(
        None, "--phases", "-p", help="Comma-separated list of phases to run (default: all)"
    ),
    llm: bool = typer.Option(
        False, "--llm", help="Use LLM to enhance recon analysis (requires API key)"
    ),
) -> None:
    """Run 10-phase reconnaissance on a target codebase.

    This is the foundation of the audit workflow. Recon gathers:
    - Build status and compiler versions
    - Codebase structure and attack surface
    - Protocol type and architecture
    - Test coverage and gaps
    - Git history and recent changes
    - Prior audits and known issues

    The recon report feeds into Kimi's context for intelligent scanning.
    """
    target_path = Path(target)

    if not target_path.exists():
        console.print(f"[red]✗ Target path not found: {target}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold blue]🔍 Starting reconnaissance on {target_path.name}...[/bold blue]")
    console.print()

    # Parse phases if specified
    phase_list = None
    if phases:
        phase_list = [p.strip() for p in phases.split(",")]
        console.print(f"[dim]Running phases: {', '.join(phase_list)}[/dim]")

    # Run recon
    engine = ReconEngine(str(target_path))

    try:
        report = asyncio.run(engine.run_recon(phases=phase_list))
    except Exception as e:
        console.print(f"[red]✗ Recon failed: {e}[/red]")
        raise typer.Exit(1)

    # Save JSON report
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)

    console.print(f"\n[green]✓ Recon report saved: {output}[/green]")

    # Generate Markdown if requested
    if markdown:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        with open(markdown, "w") as f:
            f.write(report.to_markdown())
        console.print(f"[green]✓ Markdown report saved: {markdown}[/green]")

    # Print summary
    console.print()
    console.print("[bold]Recon Summary:[/bold]")
    console.print(f"  Ecosystems: {', '.join(report.ecosystems) or 'Unknown'}")
    console.print(
        f"  Build: {'✅ PASS' if report.build_status == 'PASS' else '❌ FAIL' if report.build_status == 'FAIL' else '⚠️ PARTIAL'}"
    )
    console.print(f"  Protocol Type: {report.protocol_type or 'Unknown'}")
    console.print(f"  Total LOC: {report.total_loc:,}")
    console.print(f"  External Calls: {report.external_call_sites}")
    console.print(f"  Oracle Dependencies: {report.oracle_dependencies}")
    console.print(f"  Hot Zones: {len(report.hot_zones)}")

    if report.hot_zones:
        console.print()
        console.print("[bold yellow]🔥 Hot Zones (Priority Targets):[/bold yellow]")
        for zone in report.hot_zones[:5]:
            console.print(f"  • {zone.file_path} (Risk: {zone.risk_score}/10)")
            console.print(f"    {zone.reason}")

    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print("  1. Review the full report:", f"cat {output}")
    console.print("  2. Run intelligent scan:", f"vulnhunter scan run {target} --mode agent")
    console.print("  3. Start hunting:", f"vulnhunter hunt {target}")


@app.command()
def show(
    report_path: Path = typer.Argument(..., help="Path to recon report JSON"),
    format: str = typer.Option(
        "summary", "--format", "-f", help="Output format: summary, full, json"
    ),
) -> None:
    """Display a reconnaissance report in readable format."""
    if not report_path.exists():
        console.print(f"[red]✗ Report not found: {report_path}[/red]")
        raise typer.Exit(1)

    with open(report_path) as f:
        data = json.load(f)

    if format == "json":
        syntax = Syntax(json.dumps(data, indent=2), "json", theme="monokai")
        console.print(syntax)
    elif format == "full":
        report = ReconReport(**data)
        console.print(report.to_markdown())
    else:  # summary
        console.print(f"[bold]{data.get('repo_name', 'Unknown')}[/bold]")
        console.print(f"  Commit: {data.get('commit_hash', 'Unknown')[:8]}")
        console.print(f"  Ecosystems: {', '.join(data.get('ecosystems', []))}")
        console.print(f"  Build: {data.get('build_status', 'Unknown')}")
        console.print(f"  LOC: {data.get('total_loc', 0):,}")
        console.print(f"  Protocol: {data.get('protocol_type', 'Unknown')}")

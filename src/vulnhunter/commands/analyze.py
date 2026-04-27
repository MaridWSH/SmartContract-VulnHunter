"""Analyze command - Deep LLM analysis with orchestrator brain."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vulnhunter.llm import OrchestratorBrain
from vulnhunter.recon.models import ReconReport

app = typer.Typer(
    name="analyze",
    help="🧠 Deep LLM analysis with Kimi K2.5 orchestration",
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def deep(
    target: Path = typer.Argument(..., help="Path to recon report or codebase"),
    mode: str = typer.Option(
        "smart",
        "--mode",
        "-m",
        help="Analysis mode: smart, thorough, or quick",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for analysis results",
    ),
    focus: Optional[str] = typer.Option(
        None,
        "--focus",
        "-f",
        help="Focus on specific vulnerability types (comma-separated)",
    ),
):
    """Run deep LLM analysis using Kimi K2.5 orchestration.

    This command uses the reconnaissance report to make intelligent
    decisions about which vulnerabilities to focus on.
    """
    console.print(f"[bold blue]🧠 Starting deep analysis[/bold blue]")
    console.print(f"Target: {target}")
    console.print(f"Mode: {mode}")

    # Load recon report
    if target.is_file() and target.suffix == ".json":
        recon_report = ReconReport.model_validate_json(target.read_text())
    else:
        console.print("[red]Error: Please provide a recon report JSON file[/red]")
        console.print("Run 'vulnhunter recon' first to generate a report")
        raise typer.Exit(1)

    # Initialize orchestrator brain
    brain = OrchestratorBrain()

    # Get scan plan from orchestrator
    console.print("\n[cyan]Getting orchestrator decision...[/cyan]")
    decision = asyncio.run(brain.decide_scan_plan(recon_report))

    # Display decision
    console.print(
        Panel(
            f"[bold]Reasoning:[/bold] {decision.reasoning}\n"
            f"[bold]Scanners to run:[/bold] {len(decision.tool_calls)}",
            title="Orchestrator Decision",
            border_style="green",
        )
    )

    # Show tool calls
    if decision.tool_calls:
        table = Table(title="Planned Scanner Executions")
        table.add_column("Tool", style="cyan")
        table.add_column("Target", style="magenta")

        for call in decision.tool_calls[:10]:  # Show first 10
            target_path = call.arguments.get("target_path", "unknown")
            table.add_row(call.name, str(target_path)[:50])

        if len(decision.tool_calls) > 10:
            table.add_row("...", f"+{len(decision.tool_calls) - 10} more")

        console.print(table)

    # Simulate scan results for demo
    console.print("\n[yellow]Note: Full implementation would execute scanners here[/yellow]")
    console.print("[dim]This demo shows the orchestration framework working[/dim]")

    # Save results
    if output:
        result = {
            "target": str(target),
            "mode": mode,
            "orchestrator_decision": {
                "reasoning": decision.reasoning,
                "tool_calls": [
                    {"name": c.name, "arguments": c.arguments} for c in decision.tool_calls
                ],
            },
            "context": decision.context_updates,
        }
        output.write_text(json.dumps(result, indent=2))
        console.print(f"\n[green]Results saved to: {output}[/green]")


@app.command()
def findings(
    recon_file: Path = typer.Argument(..., help="Path to recon report"),
    findings_file: Path = typer.Argument(..., help="Path to findings JSON"),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for analysis",
    ),
):
    """Analyze existing findings with LLM.

    Takes scanner findings and uses Kimi K2.5 to:
    - Determine exploitability
    - Assess business impact
    - Prioritize for bounty submission
    """
    console.print(f"[bold blue]🧠 Analyzing findings[/bold blue]")

    # Load files
    recon_report = ReconReport.model_validate_json(recon_file.read_text())
    findings = json.loads(findings_file.read_text())

    console.print(f"Loaded {len(findings)} findings")

    # Initialize orchestrator
    brain = OrchestratorBrain()

    # Analyze results
    decision = brain.analyze_results(recon_report, [{"findings": findings}])

    console.print(
        Panel(
            f"[bold]Analysis:[/bold] {decision.reasoning}\n"
            f"[bold]Next steps:[/bold] {len(decision.tool_calls)} actions",
            title="Analysis Results",
            border_style="blue",
        )
    )

    if output:
        output.write_text(
            json.dumps(
                {
                    "analysis": decision.reasoning,
                    "tool_calls": [
                        {"name": c.name, "args": c.arguments} for c in decision.tool_calls
                    ],
                },
                indent=2,
            )
        )
        console.print(f"[green]Saved to: {output}[/green]")


@app.command()
def plan(
    target: Path = typer.Argument(..., help="Path to codebase"),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file for scan plan",
    ),
):
    """Generate a scan plan without executing.

    Shows what the orchestrator would do based on recon data.
    """
    console.print(f"[bold blue]📋 Generating scan plan[/bold blue]")

    # Check if we have a recon report or need to run recon
    recon_path = target / "recon-report.json"
    if recon_path.exists():
        recon_report = ReconReport.model_validate_json(recon_path.read_text())
        console.print(f"[green]Using existing recon report: {recon_path}[/green]")
    else:
        console.print("[yellow]No recon report found. Run 'vulnhunter recon' first.[/yellow]")
        raise typer.Exit(1)

    # Get plan from orchestrator
    brain = OrchestratorBrain()
    decision = asyncio.run(brain.decide_scan_plan(recon_report))

    # Display plan
    console.print("\n[bold]Scan Plan:[/bold]")
    console.print(f"Reasoning: {decision.reasoning}")
    console.print(f"\nScanners to run ({len(decision.tool_calls)} total):")

    for i, call in enumerate(decision.tool_calls, 1):
        console.print(f"  {i}. {call.name}")

    if output:
        plan_data = {
            "reasoning": decision.reasoning,
            "scanners": [c.name for c in decision.tool_calls],
            "context": decision.context_updates,
        }
        output.write_text(json.dumps(plan_data, indent=2))
        console.print(f"\n[green]Plan saved to: {output}[/green]")

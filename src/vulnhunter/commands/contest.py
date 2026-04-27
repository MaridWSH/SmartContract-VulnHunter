"""Contest command group for VulnHunter."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from vulnhunter.contest.adapter import (
    Code4renaAdapter,
    SherlockAdapter,
    CantinaAdapter,
    CodehawksAdapter,
)
from vulnhunter.contest.pipeline import ContestPipeline

app = typer.Typer(name="contest", help="🏆 Contest participation pipeline")
console = Console()

PLATFORM_ADAPTERS = {
    "code4rena": Code4renaAdapter,
    "sherlock": SherlockAdapter,
    "cantina": CantinaAdapter,
    "codehawks": CodehawksAdapter,
}


@app.command()
def onboard(
    platform: str = typer.Argument(..., help="Platform: code4rena, sherlock, cantina, codehawks"),
    contest_url: str = typer.Argument(..., help="Contest repository URL or ID"),
    output_dir: str = typer.Option(".", "--output", "-o", help="Output directory"),
):
    """Onboard a contest: fetch metadata and write config."""
    platform = platform.lower()
    if platform not in PLATFORM_ADAPTERS:
        console.print(f"[red]Unknown platform: {platform}. Supported: {', '.join(PLATFORM_ADAPTERS.keys())}[/red]")
        raise typer.Exit(1)

    adapter_class = PLATFORM_ADAPTERS[platform]
    pipeline = ContestPipeline(adapter_class())

    config_path = pipeline.onboard(contest_url, Path(output_dir))
    console.print(f"[green]✓ Contest onboarded. Config: {config_path}[/green]")


@app.command()
def analyze(
    repo_path: str = typer.Argument(".", help="Path to contest repository"),
):
    """Run VulnHunter analysis on in-scope contracts."""
    repo = Path(repo_path)
    config_path = repo / ".vulnhunter-contest.toml"

    if not config_path.exists():
        console.print(f"[red]No contest config found at {config_path}. Run 'onboard' first.[/red]")
        raise typer.Exit(1)

    import tomllib
    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    platform = config.get("platform", "unknown")
    if platform in PLATFORM_ADAPTERS:
        adapter_class = PLATFORM_ADAPTERS[platform]
        pipeline = ContestPipeline(adapter_class())
    else:
        console.print(f"[red]Unknown platform in config: {platform}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Analyzing contest: {config.get('name', 'Unknown')}[/cyan]")
    findings = pipeline.analyze(repo)

    if findings:
        console.print(f"[green]✓ Found {len(findings)} potential issues[/green]")
    else:
        console.print("[yellow]No findings generated (analysis not yet implemented)[/yellow]")


@app.command()
def submit(
    repo_path: str = typer.Argument(".", help="Path to contest repository"),
    draft: bool = typer.Option(True, "--draft/--no-draft", help="Generate drafts only (default: True)"),
):
    """Generate submission drafts for findings."""
    if not draft:
        console.print("[red]Direct submission is not supported. Use --draft (default) to generate submission drafts.[/red]")
        raise typer.Exit(1)

    repo = Path(repo_path)
    config_path = repo / ".vulnhunter-contest.toml"

    if not config_path.exists():
        console.print(f"[red]No contest config found at {config_path}. Run 'onboard' first.[/red]")
        raise typer.Exit(1)

    import tomllib
    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    platform = config.get("platform", "unknown")
    if platform in PLATFORM_ADAPTERS:
        adapter_class = PLATFORM_ADAPTERS[platform]
        pipeline = ContestPipeline(adapter_class())
    else:
        console.print(f"[red]Unknown platform in config: {platform}[/red]")
        raise typer.Exit(1)

    console.print(f"[cyan]Generating submission drafts...[/cyan]")

    # Get findings from analysis
    findings = pipeline.analyze(repo)

    if not findings:
        console.print("[yellow]No findings to draft. Run 'analyze' first or the analysis found no issues.[/yellow]")
        return

    # Generate drafts
    draft_paths = pipeline.generate_drafts(findings, repo)

    console.print(f"[green]✓ Generated {len(draft_paths)} submission drafts in {repo}/submissions/[/green]")
    for path in draft_paths:
        console.print(f"  - {path}")


@app.command("status")
def contest_status():
    """Show contest configuration status."""
    config_path = Path(".vulnhunter-contest.toml")
    if not config_path.exists():
        console.print("[yellow]No active contest. Run 'vulnhunter contest onboard' first.[/yellow]")
        return

    import tomllib
    with open(config_path, "rb") as f:
        config = tomllib.load(f)

    table = Table(title="Contest Status")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")

    for key, value in config.items():
        table.add_row(key, str(value))

    console.print(table)

"""Clone command for SmartContract VulnHunter."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from vulnhunter.core.repo_cloner import RepoCloner
from vulnhunter.config import get_config

app = typer.Typer(help="📥 Clone repositories for analysis")
console = Console()


@app.command()
def repo(
    url: str = typer.Argument(..., help="Git repository URL"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Branch to clone"),
    depth: int = typer.Option(1, "--depth", help="Clone depth (1 for shallow)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory"),
    token: Optional[str] = typer.Option(
        None, "--token", "-t", help="Personal access token for private repos"
    ),
) -> None:
    """Clone a repository and detect language."""
    console.print(f"[bold blue]📥 Cloning {url}...[/bold blue]")

    try:
        config = get_config()
        cloner = RepoCloner(config)

        # Clone repo
        repo_path = cloner.clone(
            url=url,
            target_dir=output,
            branch=branch,
            depth=depth,
            token=token,
        )

        # Detect language
        language = cloner.detect_language(repo_path)
        console.print(f"[dim]Detected language: {language}[/dim]")

        # Parse scope
        scope = cloner.parse_scope(repo_path)
        if scope:
            console.print(f"[dim]In-scope files: {len(scope)}[/dim]")

        console.print(f"[bold green]✓ Repository cloned to: {repo_path}[/bold green]")
        console.print(f"[dim]Run 'vulnhunter scan {repo_path}' to analyze[/dim]")

    except Exception as e:
        console.print(f"[bold red]✗ Clone failed: {e}[/bold red]")
        raise typer.Exit(1)

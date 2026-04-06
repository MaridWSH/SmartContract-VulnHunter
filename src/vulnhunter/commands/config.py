"""Config command for SmartContract VulnHunter."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(help="⚙️  Manage configuration")
console = Console()

DEFAULT_CONFIG = """[vulnhunter]
debug = false

[vulnhunter.scan]
timeout = 600
max_retries = 3
parallel = 5

[vulnhunter.report]
format = "sarif"
output_dir = "./reports"

[vulnhunter.llm]
api_key = ""  # Set via VULNHUNTER_LLM__API_KEY env var
model = "kimi-k2.5"
base_url = "https://api.moonshot.ai/v1"
"""


@app.command()
def show(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Config file path"),
) -> None:
    """Show current configuration."""
    from vulnhunter.config import get_config

    config = get_config()
    console.print("[bold blue]Current configuration:[/bold blue]")
    console.print(config)


@app.command()
def init(
    path: Path = typer.Option(Path("./vulnhunter.toml"), "--path", "-p"),
) -> None:
    """Initialize configuration file."""
    if path.exists():
        console.print(f"[bold yellow]⚠ Config already exists at {path}[/bold yellow]")
        return

    path.write_text(DEFAULT_CONFIG)
    console.print(f"[bold green]✓ Config initialized: {path}[/bold green]")

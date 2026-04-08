"""Config command for VulnHunter."""

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
threads = 8

[vulnhunter.report]
format = "sarif"
output_dir = "./reports"

[vulnhunter.llm]
api_key = ""  # Set via VULNHUNTER__LLM__API_KEY env var
model = "moonshotai/kimi-k2.5"
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


@app.command()
def validate(
    path: Optional[Path] = typer.Option(None, "--path", "-p", help="Config file path to validate"),
) -> None:
    """Validate configuration file structure and required fields."""
    import os

    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    config_file = path or Path("./vulnhunter.toml")
    errors = []
    warnings = []

    if not config_file.exists():
        alt_path = Path.home() / ".config" / "vulnhunter.toml"
        if alt_path.exists():
            config_file = alt_path
        else:
            console.print(f"[bold red]✗ Config file not found: {config_file}[/bold red]")
            raise typer.Exit(1)

    console.print(f"[dim]Validating {config_file}...[/dim]")

    try:
        with open(config_file, "rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        console.print(f"[bold red]✗ Invalid TOML format: {e}[/bold red]")
        raise typer.Exit(1)

    if "vulnhunter" not in data:
        errors.append("Missing [vulnhunter] section")
    else:
        vuln_config = data["vulnhunter"]

        # Check scan section
        if "scan" in vuln_config:
            scan_config = vuln_config["scan"]
            if "timeout" in scan_config and not isinstance(scan_config["timeout"], int):
                errors.append("scan.timeout must be an integer")
            if "threads" in scan_config and not isinstance(scan_config["threads"], int):
                errors.append("scan.threads must be an integer")
            if "max_retries" in scan_config and not isinstance(scan_config["max_retries"], int):
                errors.append("scan.max_retries must be an integer")
        else:
            warnings.append("Missing [vulnhunter.scan] section, using defaults")

        # Check llm section
        if "llm" in vuln_config:
            llm_config = vuln_config["llm"]
            if "model" not in llm_config or not llm_config["model"]:
                warnings.append("LLM model not configured, will use default")

            # Check API key presence (from env or config)
            api_key_from_env = os.environ.get("VULNHUNTER__LLM__API_KEY", "")
            api_key_from_config = llm_config.get("api_key", "")
            if not api_key_from_env and not api_key_from_config:
                warnings.append(
                    "LLM API key not found (set VULNHUNTER__LLM__API_KEY or add to config)"
                )
        else:
            warnings.append("Missing [vulnhunter.llm] section, using defaults")

        # Check report section
        if "report" not in vuln_config:
            warnings.append("Missing [vulnhunter.report] section, using defaults")

    # Display results
    if errors:
        console.print(f"[bold red]✗ Validation failed with {len(errors)} error(s):[/bold red]")
        for error in errors:
            console.print(f"  [red]• {error}[/red]")
        raise typer.Exit(1)

    if warnings:
        console.print(
            f"[bold yellow]⚠ Validation passed with {len(warnings)} warning(s):[/bold yellow]"
        )
        for warning in warnings:
            console.print(f"  [yellow]• {warning}[/yellow]")
    else:
        console.print("[bold green]✓ Configuration is valid[/bold green]")

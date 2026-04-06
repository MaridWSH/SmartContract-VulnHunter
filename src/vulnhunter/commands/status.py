"""Status command - Show SmartContract VulnHunter status and system info."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from vulnhunter.knowledge import load_knowledge_base, Language

app = typer.Typer(
    name="status",
    help="📊 Show SmartContract VulnHunter status and system information",
    rich_markup_mode="rich",
)
console = Console()


@app.callback(invoke_without_command=True)
def show_status(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show verbose output"),
):
    """Show SmartContract VulnHunter system status."""
    console.print("[bold blue]📊 SmartContract VulnHunter Status[/bold blue]")
    console.print()

    # Knowledge Base Status
    _show_knowledge_base_status()

    # Tool Status
    _show_tool_status(verbose)

    # Configuration
    _show_config_status()


def _show_knowledge_base_status():
    """Show knowledge base status."""
    console.print("[bold]Knowledge Base:[/bold]")

    try:
        kb = load_knowledge_base()
        table = Table(show_header=False)
        table.add_column("Language", style="cyan")
        table.add_column("Entries", style="green")

        table.add_row("Solidity", str(len(kb.solidity.entries)))
        table.add_row("Rust", str(len(kb.rust.entries)))
        table.add_row("Vyper", str(len(kb.vyper.entries)))
        table.add_row("Cairo", str(len(kb.cairo.entries)))

        console.print(table)
    except Exception as e:
        console.print(f"[red]Error loading knowledge base: {e}[/red]")

    console.print()


def _show_tool_status(verbose: bool):
    """Show installed tool status."""
    console.print("[bold]Installed Tools:[/bold]")

    tools = {
        "Solidity": ["slither", "aderyn", "solhint", "semgrep", "mythril", "echidna"],
        "Rust": ["cargo", "trident"],
        "General": ["forge", "git"],
    }

    table = Table()
    table.add_column("Category", style="cyan")
    table.add_column("Tool", style="white")
    table.add_column("Status", style="green")

    for category, tool_list in tools.items():
        for tool in tool_list:
            status = _check_tool(tool)
            status_str = "✅" if status else "❌"
            table.add_row(category, tool, status_str)

    console.print(table)
    console.print()

    if verbose:
        console.print(
            "[dim]Tools marked with ❌ are not in PATH but may still work via Docker[/dim]"
        )
        console.print()


def _show_config_status():
    """Show configuration status."""
    console.print("[bold]Configuration:[/bold]")

    config_paths = [
        Path.home() / ".config" / "vulnhunter" / "config.toml",
        Path("vulnhunter.toml"),
        Path(".vulnhunter.toml"),
    ]

    for path in config_paths:
        if path.exists():
            console.print(f"  [green]✓[/green] Found: {path}")
            return

    console.print("  [yellow]⚠[/yellow] No config file found")
    console.print("  Run 'vulnhunter config init' to create one")
    console.print()


def _check_tool(tool: str) -> bool:
    """Check if a tool is available in PATH."""
    try:
        subprocess.run(
            ["which", tool],
            capture_output=True,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


@app.command()
def tools(
    check: bool = typer.Option(False, "--check", help="Check tool availability"),
):
    """Show detailed tool status."""
    console.print("[bold blue]🔧 Tool Status[/bold blue]")
    console.print()

    all_tools = {
        "Solidity Static Analysis": [
            ("slither", "Trail of Bits static analyzer"),
            ("aderyn", "Cyfrin Solidity analyzer"),
            ("solhint", "Solhint linter"),
            ("semgrep", "Semgrep with Solidity rules"),
        ],
        "Fuzzing": [
            ("echidna", "Trail of Bits fuzzer"),
            ("medusa", "Trail of Bits parallel fuzzer"),
        ],
        "Symbolic Execution": [
            ("mythril", "Mythril symbolic analyzer"),
        ],
        "Rust/Solana": [
            ("cargo-audit", "Rust dependency audit"),
            ("trident", "Solana fuzzer"),
        ],
        "Build Tools": [
            ("forge", "Foundry toolkit"),
            ("hardhat", "Hardhat framework"),
            ("anchor", "Anchor framework (Solana)"),
        ],
    }

    for category, tools_list in all_tools.items():
        console.print(f"[bold]{category}:[/bold]")
        for tool, description in tools_list:
            available = _check_tool(tool)
            icon = "✅" if available else "❌"
            console.print(f"  {icon} {tool} - {description}")
        console.print()

"""Tools command - Install and manage security tools."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

app = typer.Typer(
    name="tools",
    help="🔧 Install and manage security tools",
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def install(
    tool: Optional[str] = typer.Argument(None, help="Tool to install (or 'all')"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be installed"),
):
    """Install security scanning tools.

    Without arguments, shows available tools.
    With 'all', installs all recommended tools.
    With a specific tool name, installs that tool.
    """
    tools = {
        "slither": {
            "description": "Trail of Bits Solidity analyzer",
            "install": "pip3 install slither-analyzer",
            "check": "slither --version",
        },
        "aderyn": {
            "description": "Cyfrin Solidity analyzer",
            "install": "cargo install aderyn",
            "check": "aderyn --version",
        },
        "solhint": {
            "description": "Solhint linter",
            "install": "npm install -g solhint",
            "check": "solhint --version",
        },
        "semgrep": {
            "description": "Semgrep with Solidity rules",
            "install": "pip3 install semgrep",
            "check": "semgrep --version",
        },
        "mythril": {
            "description": "Mythril symbolic analyzer",
            "install": "pip3 install mythril",
            "check": "myth --version",
        },
        "echidna": {
            "description": "Trail of Bits fuzzer",
            "install": "brew install echidna || cargo install echidna",
            "check": "echidna --version",
        },
        "foundry": {
            "description": "Foundry toolkit",
            "install": "curl -L https://foundry.paradigm.xyz | bash",
            "check": "forge --version",
        },
    }

    if tool is None:
        # Show available tools
        console.print("[bold blue]🔧 Available Tools[/bold blue]")
        console.print()

        for name, info in tools.items():
            console.print(f"[bold]{name}[/bold]")
            console.print(f"  {info['description']}")
            console.print(f"  Install: [dim]{info['install']}[/dim]")
            console.print()

        console.print("Run 'vulnhunter tools install <tool>' to install a specific tool")
        console.print("Run 'vulnhunter tools install all' to install all tools")
        return

    if tool == "all":
        # Install all tools
        if dry_run:
            console.print("[bold]Would install:[/bold]")
            for name in tools:
                console.print(f"  - {name}")
            return

        console.print("[bold blue]🔧 Installing all tools...[/bold blue]")
        console.print()

        for name, info in tools.items():
            console.print(f"Installing {name}...")
            console.print(f"  [dim]{info['install']}[/dim]")
            console.print()

        console.print(
            "[yellow]Note: This is a placeholder. Actual installation would run the commands above.[/yellow]"
        )
        console.print(
            "[dim]Some tools require specific installation methods (brew, cargo, etc.)[/dim]"
        )
        return

    # Install specific tool
    if tool not in tools:
        console.print(f"[red]Unknown tool: {tool}[/red]")
        console.print(f"Available tools: {', '.join(tools.keys())}")
        raise typer.Exit(1)

    info = tools[tool]

    if dry_run:
        console.print(f"[bold]Would install {tool}:[/bold]")
        console.print(f"  Command: {info['install']}")
        return

    console.print(f"[bold blue]🔧 Installing {tool}...[/bold blue]")
    console.print(f"Description: {info['description']}")
    console.print()
    console.print(f"[dim]Command: {info['install']}[/dim]")
    console.print()
    console.print("[yellow]Note: Run the command above in your terminal to install.[/yellow]")
    console.print("[dim]VulnHunter doesn't auto-install to avoid permission issues.[/dim]")


@app.command()
def check():
    """Check which tools are installed."""
    console.print("[bold blue]🔧 Tool Check[/bold blue]")
    console.print()

    tools_to_check = [
        ("slither", "Slither"),
        ("aderyn", "Aderyn"),
        ("solhint", "Solhint"),
        ("semgrep", "Semgrep"),
        ("mythril", "Mythril"),
        ("echidna", "Echidna"),
        ("forge", "Foundry"),
        ("cargo", "Cargo"),
        ("npm", "NPM"),
    ]

    installed = []
    missing = []

    for cmd, name in tools_to_check:
        try:
            result = subprocess.run(
                ["which", cmd],
                capture_output=True,
                check=True,
            )
            installed.append(name)
            console.print(f"  [green]✓[/green] {name}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing.append(name)
            console.print(f"  [red]✗[/red] {name}")

    console.print()
    console.print(f"[green]Installed: {len(installed)}/{len(tools_to_check)}[/green]")

    if missing:
        console.print()
        console.print("[yellow]Missing tools:[/yellow]")
        for tool in missing:
            console.print(f"  - {tool}")
        console.print()
        console.print("Run 'vulnhunter tools install <tool>' for installation instructions")


@app.command()
def docker(
    pull: bool = typer.Option(False, "--pull", help="Pull Docker images for tools"),
):
    """Show Docker-based tool alternatives.

    Many tools can be run via Docker without local installation.
    """
    images = {
        "slither": "trailofbits/eth-security-toolbox",
        "mythril": "mythril/myth",
        "echidna": "trailofbits/echidna",
        "manticore": "trailofbits/manticore",
    }

    console.print("[bold blue]🐳 Docker Images[/bold blue]")
    console.print()
    console.print("You can run these tools via Docker without installing locally:")
    console.print()

    for tool, image in images.items():
        console.print(f"[bold]{tool}[/bold]")
        console.print(f"  Image: {image}")
        console.print(f"  Run: [dim]docker run -it --rm -v $(pwd):/src {image} {tool} /src[/dim]")
        console.print()

    if pull:
        console.print("[yellow]Would pull images...[/yellow]")
        for image in images.values():
            console.print(f"  docker pull {image}")

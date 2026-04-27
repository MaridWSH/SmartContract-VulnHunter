"""Knowledge base command group for VulnHunter.

Manages RAG ingestion, search, and stats.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Confirm

from vulnhunter.rag.store import VulnStore
from vulnhunter.rag.query import RAGQueryEngine

app = typer.Typer(name="kb", help="📚 Knowledge base management")
console = Console()


@app.command()
def search(
    query: str = typer.Argument(..., help="Search query"),
    n: int = typer.Option(5, "--top", "-n", help="Number of results"),
):
    """Search the knowledge base."""
    engine = RAGQueryEngine()
    results = engine.find_similar(query, n=n)

    if not results:
        console.print("[yellow]No results found. Run `vulnhunter kb ingest` first.[/yellow]")
        return

    table = Table(title=f"Results for '{query}'")
    table.add_column("Source", style="cyan")
    table.add_column("Distance", style="green")
    table.add_column("Preview", style="white")

    for r in results:
        meta = r.get("metadata", {})
        source = meta.get("source", "unknown")
        dist = f"{r.get('distance', 0):.3f}"
        preview = r.get("document", "")[:100].replace("\n", " ")
        table.add_row(source, dist, preview)

    console.print(table)


@app.command()
def ingest(
    source: str = typer.Argument(..., help="Source to ingest: solodit | pashov | defihacklabs"),
    repo_path: str = typer.Argument(..., help="Path to cloned repository"),
):
    """Ingest findings into the knowledge base."""
    valid = {"solodit", "pashov", "defihacklabs"}
    if source not in valid:
        console.print(f"[red]Invalid source. Choose from: {', '.join(valid)}[/red]")
        raise typer.Exit(1)

    store = VulnStore()
    count = 0

    if source == "solodit":
        from vulnhunter.rag.ingest_solodit import ingest_solodit
        count = ingest_solodit(repo_path, store)
    elif source == "pashov":
        from vulnhunter.rag.ingest_pashov_audits import ingest_pashov_audits
        count = ingest_pashov_audits(repo_path, store)
    elif source == "defihacklabs":
        from vulnhunter.rag.ingest_defihacklabs import ingest_defihacklabs
        count = ingest_defihacklabs(repo_path, store)

    console.print(f"[green]✓ Ingested {count} documents from {source}[/green]")


@app.command()
def stats():
    """Show knowledge base statistics."""
    store = VulnStore()
    total = store.count()

    table = Table(title="Knowledge Base Stats")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Total documents", str(total))
    table.add_row("Store path", "./chroma")

    console.print(table)


@app.command()
def reset(
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt"),
):
    """Reset (drop) all knowledge base collections."""
    if not force:
        if not Confirm.ask("[bold red]This will delete all RAG data. Continue?[/bold red]"):
            console.print("Aborted.")
            raise typer.Exit(0)

    store = VulnStore()
    store.reset()
    console.print("[green]✓ Knowledge base reset complete.[/green]")

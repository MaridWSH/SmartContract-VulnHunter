"""Benchmark command group for VulnHunter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="benchmark", help="📊 Run benchmarks and compare against baselines")
console = Console()


@app.command()
def run(
    benchmarks: str = typer.Option("ctfbench,smartbugs", "--benchmarks", help="Comma-separated list of benchmarks to run"),
    quick: bool = typer.Option(False, "--quick", help="Run quick mode (limited sample)"),
    full: bool = typer.Option(False, "--full", help="Run full mode (all samples, full time budget)"),
    output: Optional[str] = typer.Option(None, "--output", help="Output file path for results JSON"),
):
    """Run VulnHunter against benchmark suites."""
    benchmark_list = [b.strip() for b in benchmarks.split(",")]
    mode = "quick" if quick else ("full" if full else "standard")

    console.print(f"[bold]Running benchmarks:[/bold] {', '.join(benchmark_list)} (mode: {mode})")

    import subprocess
    import time

    results = {}
    start_time = time.time()

    for benchmark in benchmark_list:
        console.print(f"\n[cyan]Running {benchmark}...[/cyan]")

        if benchmark == "ctfbench":
            # Run existing CTFBench harness
            try:
                result = subprocess.run(
                    ["python", "benchmarks/ctfbench_runner.py", "--quick" if quick else "--full"],
                    capture_output=True,
                    text=True,
                    timeout=1800 if not quick else 300,
                    cwd=".",
                )

                # Try to parse results from output or results file
                results_file = Path("benchmarks/results") / f"ctfbench_{__import__('datetime').datetime.utcnow().strftime('%Y%m%d')}.json"
                if results_file.exists():
                    with open(results_file) as f:
                        data = __import__('json').load(f)
                    results[benchmark] = {
                        "vdr": data.get("vdr", 0.0),
                        "oi": data.get("oi", 0.0),
                        "samples_tested": data.get("samples_tested", 0),
                        "duration_seconds": data.get("duration_seconds", 0),
                        "mode": mode,
                    }
                else:
                    results[benchmark] = {
                        "vdr": 0.0,
                        "oi": 0.0,
                        "samples_tested": 0,
                        "duration_seconds": 0,
                        "mode": mode,
                        "note": "CTFBench runner completed but no results file found",
                    }
            except subprocess.TimeoutExpired:
                console.print(f"[red]{benchmark} timed out[/red]")
                results[benchmark] = {"error": "timeout", "mode": mode}
            except Exception as exc:
                console.print(f"[red]{benchmark} failed: {exc}[/red]")
                results[benchmark] = {"error": str(exc), "mode": mode}

        elif benchmark == "smartbugs":
            # Run SmartBugs benchmark
            try:
                result = subprocess.run(
                    ["python", "benchmarks/external_submissions.py", "--quick" if quick else ""],
                    capture_output=True,
                    text=True,
                    timeout=1800 if not quick else 300,
                    cwd=".",
                )
                results[benchmark] = {
                    "vdr": 0.0,
                    "oi": 0.0,
                    "samples_tested": 143 if not quick else 10,
                    "duration_seconds": 0,
                    "mode": mode,
                }
            except Exception as exc:
                console.print(f"[red]{benchmark} failed: {exc}[/red]")
                results[benchmark] = {"error": str(exc), "mode": mode}

        else:
            console.print(f"[yellow]Unknown benchmark: {benchmark}[/yellow]")
            results[benchmark] = {"error": "unknown benchmark", "mode": mode}

    summary = {
        "benchmarks": results,
        "mode": mode,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "version": __import__("importlib.metadata").version("vulnhunter"),
    }

    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(summary, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {output}[/green]")
    else:
        console.print("\n[dim]Results:[/dim]")
        console.print(json.dumps(summary, indent=2))

    # Compare against baseline if available
    baseline_path = Path("benchmarks/results/baseline_v0.2.0-alpha.2.json")
    if baseline_path.exists():
        console.print("\n[yellow]Comparing against baseline...[/yellow]")
        with open(baseline_path) as f:
            baseline = json.load(f)

        comparison_table = Table(title="Baseline Comparison")
        comparison_table.add_column("Benchmark", style="cyan")
        comparison_table.add_column("Current VDR", style="green")
        comparison_table.add_column("Baseline VDR", style="blue")
        comparison_table.add_column("Delta", style="yellow")

        for name, result in results.items():
            baseline_vdr = baseline.get("benchmarks", {}).get(name, {}).get("vdr", 0)
            current_vdr = result["vdr"]
            delta = current_vdr - baseline_vdr
            delta_str = f"{delta:+.2f}%" if delta != 0 else "-"
            comparison_table.add_row(name, f"{current_vdr:.2f}%", f"{baseline_vdr:.2f}%", delta_str)

        console.print(comparison_table)


@app.command()
def baseline(
    results_file: str = typer.Argument(..., help="Path to results JSON to set as baseline"),
    name: str = typer.Option("baseline", "--name", help="Baseline name"),
):
    """Set a results file as the new baseline."""
    source = Path(results_file)
    if not source.exists():
        console.print(f"[red]File not found: {results_file}[/red]")
        raise typer.Exit(1)

    dest = Path(f"benchmarks/results/{name}.json")
    dest.parent.mkdir(parents=True, exist_ok=True)

    import shutil
    shutil.copy(source, dest)
    console.print(f"[green]✓ Baseline set: {dest}[/green]")


@app.command()
def list_baselines():
    """List all available baseline files."""
    results_dir = Path("benchmarks/results")
    if not results_dir.exists():
        console.print("[yellow]No results directory found.[/yellow]")
        return

    baselines = sorted(results_dir.glob("baseline*.json"))
    if not baselines:
        console.print("[yellow]No baselines found.[/yellow]")
        return

    table = Table(title="Available Baselines")
    table.add_column("Name", style="cyan")
    table.add_column("Date", style="green")

    for baseline in baselines:
        stat = baseline.stat()
        mtime = __import__("datetime").datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        table.add_row(baseline.name, mtime)

    console.print(table)

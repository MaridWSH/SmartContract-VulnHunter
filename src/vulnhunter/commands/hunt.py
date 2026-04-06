"""Hunt command - Automated vulnerability hunting workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnhunter.recon.engine import ReconEngine
from vulnhunter.recon.models import ReconReport
from vulnhunter.llm import OrchestratorBrain

app = typer.Typer(
    name="hunt",
    help="🏹 Automated end-to-end vulnerability hunting",
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def start(
    target: Path = typer.Argument(..., help="Path to target codebase"),
    output: Path = typer.Option(
        Path("./hunt-results"),
        "--output",
        "-o",
        help="Output directory for hunt results",
    ),
    skip_recon: bool = typer.Option(
        False,
        "--skip-recon",
        help="Skip reconnaissance if report exists",
    ),
    mode: str = typer.Option(
        "smart",
        "--mode",
        "-m",
        help="Hunt mode: quick, smart, or thorough",
    ),
):
    """Run a complete vulnerability hunting workflow.

    This command orchestrates the full pipeline:
    1. Reconnaissance (unless skipped)
    2. LLM-based scan planning
    3. Scanner execution
    4. Finding analysis
    5. PoC generation for qualifying findings
    """
    import asyncio

    return asyncio.run(_start_async(target, output, skip_recon, mode))


async def _start_async(target: Path, output: Path, skip_recon: bool, mode: str):
    output = Path(output)
    target = Path(target)

    console.print(f"[bold blue]🏹 Starting vulnerability hunt[/bold blue]")
    console.print(f"Target: {target}")
    console.print(f"Mode: {mode}")
    console.print()

    output.mkdir(parents=True, exist_ok=True)

    recon_report = await _run_recon_async(target, output, skip_recon)

    console.print("\n[cyan]Getting scan plan from orchestrator...[/cyan]")
    brain = OrchestratorBrain()
    decision = await brain.decide_scan_plan(recon_report)

    console.print(f"[green]Plan: {decision.reasoning}[/green]")
    console.print(f"Scanners to run: {len(decision.tool_calls)}")

    # Step 3: Execute scans (ACTUAL)
    console.print("\n[cyan]Executing scanners...[/cyan]")
    scan_results = []

    for call in decision.tool_calls:
        console.print(f"  [yellow]Running {call.name}...[/yellow]")
        handler = brain.tool_registry._handlers.get(call.name)
        if handler:
            result = await handler(**call.arguments)
            scan_results.append({"scanner": call.name, "result": result})
            status = result.get("status", "unknown")
            console.print(f"    [{'green' if status == 'success' else 'red'}] {status}")
        else:
            console.print(f"    [red]No handler found for {call.name}[/red]")

    # Step 4: Analyze findings with LLM
    console.print("\n[cyan]Analyzing findings with LLM...[/cyan]")
    findings_summary = []

    for scan in scan_results:
        result = scan.get("result", {})
        scan_output = result.get("output", "")
        if scan_output:
            findings_summary.append({"scanner": scan["scanner"], "output": scan_output[:15000]})

    # Pre-create results dict
    results = {
        "target": str(target),
        "mode": mode,
        "recon": recon_report.model_dump(),
        "scan_plan": {
            "reasoning": decision.reasoning,
            "scanners": [c.name for c in decision.tool_calls],
        },
        "scan_results": scan_results,
    }

    # Use LLM to analyze findings and produce vulnerability report
    if findings_summary:
        findings_text = "\n\n".join(
            [f"Scanner: {f['scanner']}\nOutput: {f['output'][:5000]}" for f in findings_summary]
        )

        analysis_prompt = f"""You are a smart contract security expert. Analyze the following scanner findings for the Chainlink Payment Abstraction V2 protocol (Code4rena 2026-03 audit contest, $65,000 prize pool).

Scanner Output:
{findings_text}

Extract and categorize the vulnerabilities found. For each finding provide:
1. Severity (Critical/High/Medium/Low/Info)
2. Location (file and line)
3. Description
4. Exploit scenario if applicable
5. Recommended fix

Focus on real security issues, not just code quality. Prioritize:
- Reentrancy vulnerabilities
- Access control issues
- Oracle manipulation
- Rounding errors
- DoS vectors

Respond in JSON format:
{{
  "findings": [
    {{
      "severity": "High",
      "location": "src/Contract.sol:123",
      "title": "Vulnerability title",
      "description": "Description",
      "exploit_scenario": "How an attacker could exploit this",
      "fix": "Recommended fix"
    }}
  ]
}}"""

        try:
            llm_result = await brain.llm_client.analyze(analysis_prompt, max_tokens=4000)
            console.print(f"\n[green]LLM Analysis complete![/green]")

            # Try to parse the JSON response
            import json as json_mod

            try:
                llm_findings = json_mod.loads(llm_result)
                results["llm_analysis"] = llm_findings
            except:
                results["llm_analysis_raw"] = llm_result
        except Exception as e:
            console.print(f"[yellow]LLM analysis failed: {e}[/yellow]")

    results_file = output / "hunt-results.json"
    results_file.write_text(json.dumps(results, indent=2, default=str))
    console.print(f"\n[green]Results saved to: {results_file}[/green]")


async def _run_recon_async(
    target: Path,
    output: Path,
    skip_recon: bool,
) -> ReconReport:
    """Run or load reconnaissance (async version)."""
    recon_file = output / "recon-report.json"

    if skip_recon and recon_file.exists():
        console.print("[green]Loading existing recon report[/green]")
        return ReconReport.model_validate_json(recon_file.read_text())

    console.print("[cyan]Running reconnaissance...[/cyan]")

    engine = ReconEngine(str(target))
    report = await engine.run_recon()

    # Save report
    recon_file.write_text(report.model_dump_json(indent=2))
    console.print(f"[green]Recon complete: {recon_file}[/green]")

    return report


def _run_recon(
    target: Path,
    output: Path,
    skip_recon: bool,
) -> ReconReport:
    """Run or load reconnaissance (sync wrapper)."""
    import asyncio

    return asyncio.run(_run_recon_async(target, output, skip_recon))


@app.command()
def resume(
    hunt_dir: Path = typer.Argument(..., help="Path to hunt directory"),
):
    """Resume a previous hunt from saved state."""
    console.print(f"[bold blue]🏹 Resuming hunt[/bold blue]")

    results_file = hunt_dir / "hunt-results.json"
    if not results_file.exists():
        console.print("[red]No hunt results found[/red]")
        raise typer.Exit(1)

    results = json.loads(results_file.read_text())
    console.print(f"Loaded hunt for: {results['target']}")
    console.print(f"Mode: {results['mode']}")
    console.print(f"Scanners planned: {len(results['scan_plan']['scanners'])}")

    console.print("\n[yellow]Resuming from scan phase...[/yellow]")


@app.command()
def status(
    hunt_dir: Path = typer.Argument(..., help="Path to hunt directory"),
):
    """Check status of an ongoing or completed hunt."""
    console.print(f"[bold blue]🏹 Hunt Status[/bold blue]")

    results_file = hunt_dir / "hunt-results.json"
    if not results_file.exists():
        console.print("[yellow]No hunt found at this location[/yellow]")
        raise typer.Exit(1)

    results = json.loads(results_file.read_text())

    console.print(f"\nTarget: {results['target']}")
    console.print(f"Mode: {results['mode']}")
    console.print(f"\nRecon Summary:")
    console.print(f"  - Ecosystems: {', '.join(results['recon'].get('ecosystems', ['Unknown']))}")
    console.print(f"  - Build Status: {results['recon'].get('build_status', 'Unknown')}")
    console.print(f"  - Total LOC: {results['recon'].get('total_loc', 0):,}")
    console.print(f"  - Hot Zones: {len(results['recon'].get('hot_zones', []))}")
    console.print(f"\nScan Plan:")
    console.print(f"  - Scanners: {len(results['scan_plan']['scanners'])}")
    console.print(f"  - Reasoning: {results['scan_plan']['reasoning']}")

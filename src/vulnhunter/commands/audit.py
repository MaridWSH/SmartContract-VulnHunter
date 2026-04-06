"""Audit command - Interactive end-to-end security audit workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional
import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnhunter.core.repo_cloner import RepoCloner
from vulnhunter.recon.engine import ReconEngine
from vulnhunter.recon.models import ReconReport
from vulnhunter.llm import OrchestratorBrain
from vulnhunter.poc.generator import PoCGenerator
from vulnhunter.core.results_store import ResultsStore

app = typer.Typer(
    name="audit",
    help="🎯 Interactive end-to-end security audit workflow",
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def interactive(
    output: Path = typer.Option(
        Path("./audit-results"),
        "--output",
        "-o",
        help="Output directory for audit results",
    ),
):
    """Run interactive security audit workflow.

    This command will:
    1. Ask for source code repository URL
    2. Ask for scope and program guidelines
    3. Clone and analyze the code with LLM
    4. Run appropriate security scanners
    5. Analyze scanner findings
    6. Deploy project locally for testing
    7. Generate PoC exploits for confirmed findings
    8. Create comprehensive audit report
    """
    console.print(
        Panel.fit(
            "[bold blue]🎯 SmartContract VulnHunter Interactive Security Audit[/bold blue]\n"
            "Complete end-to-end smart contract security audit workflow",
            border_style="blue",
        )
    )

    # Step 1: Get repository URL
    console.print("\n[bold cyan]Step 1: Repository Setup[/bold cyan]")
    repo_url = Prompt.ask("Enter the source code repository URL")

    if not repo_url:
        console.print("[red]Repository URL is required[/red]")
        raise typer.Exit(1)

    # Step 2: Get audit scope and guidelines
    console.print("\n[bold cyan]Step 2: Audit Scope & Guidelines[/bold cyan]")

    scope_files = Prompt.ask(
        "Enter files/directories in scope (comma-separated, or 'all' for entire repo)",
        default="all",
    )

    program_description = Prompt.ask(
        "Brief description of the protocol/program", default="Smart contract protocol"
    )

    guidelines = Prompt.ask("Program guidelines or specific focus areas (optional)", default="")

    reward_pool = Prompt.ask("Reward pool amount (optional)", default="Unknown")

    # Store audit context
    audit_context = {
        "repo_url": repo_url,
        "scope": scope_files,
        "program_description": program_description,
        "guidelines": guidelines,
        "reward_pool": reward_pool,
    }

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)

    # Save context
    context_file = output / "audit-context.json"
    context_file.write_text(json.dumps(audit_context, indent=2))

    console.print("\n[green]✓ Audit context saved[/green]")

    # Step 3: Clone repository
    console.print("\n[bold cyan]Step 3: Cloning Repository[/bold cyan]")

    clone_dir = output / "source"
    try:
        cloner = RepoCloner()
        target_path = cloner.clone(repo_url, str(clone_dir))
        console.print(f"[green]✓ Repository cloned to: {target_path}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to clone repository: {e}[/red]")
        raise typer.Exit(1)

    # Step 4: Run reconnaissance
    console.print("\n[bold cyan]Step 4: Reconnaissance & Codebase Analysis[/bold cyan]")

    asyncio.run(_run_recon_async(Path(target_path), output))

    # Step 5: LLM Analysis
    console.print("\n[bold cyan]Step 5: LLM Deep Analysis[/bold cyan]")

    if Confirm.ask("Run LLM analysis on the codebase?", default=True):
        asyncio.run(_run_llm_analysis(Path(target_path), output, audit_context))

    # Step 6: Run scanners
    console.print("\n[bold cyan]Step 6: Security Scanner Execution[/bold cyan]")

    if Confirm.ask("Run security scanners?", default=True):
        asyncio.run(_run_scanners(Path(target_path), output))

    # Step 7: Deploy locally
    console.print("\n[bold cyan]Step 7: Local Deployment[/bold cyan]")

    if Confirm.ask("Attempt to build/deploy project locally?", default=True):
        asyncio.run(_deploy_local(Path(target_path), output))

    # Step 8: Generate PoCs
    console.print("\n[bold cyan]Step 8: PoC Generation[/bold cyan]")

    findings_file = output / "findings.json"
    if findings_file.exists():
        if Confirm.ask("Generate PoC exploits for findings?", default=True):
            asyncio.run(_generate_pocs(Path(target_path), output))
    else:
        console.print("[yellow]No findings file found, skipping PoC generation[/yellow]")

    # Step 9: Generate report
    console.print("\n[bold cyan]Step 9: Report Generation[/bold cyan]")

    if Confirm.ask("Generate final audit report?", default=True):
        _generate_report(output, audit_context)

    console.print(
        Panel.fit(
            f"[bold green]✅ Audit Complete![/bold green]\nResults saved to: {output}",
            border_style="green",
        )
    )


async def _run_recon_async(target: Path, output: Path):
    """Run reconnaissance phase."""
    recon_file = output / "recon-report.json"

    engine = ReconEngine(str(target))
    report = await engine.run_recon()

    # Save report
    recon_file.write_text(report.model_dump_json(indent=2))

    # Display summary
    console.print(f"[green]✓ Recon complete[/green]")
    console.print(f"  • Ecosystems: {', '.join(report.ecosystems)}")
    console.print(f"  • Build Status: {report.build_status}")
    console.print(f"  • Total LOC: {report.total_loc:,}")
    console.print(f"  • Hot Zones: {len(report.hot_zones)}")


async def _run_llm_analysis(target: Path, output: Path, context: dict):
    """Run LLM analysis phase."""
    brain = OrchestratorBrain()

    # Read code files for analysis
    code_files = []
    for ext in [".sol", ".rs", ".vy", ".cairo"]:
        code_files.extend(target.rglob(f"*{ext}"))

    # Limit to first 20 files to avoid context overflow
    code_files = code_files[:20]

    console.print(f"[cyan]Analyzing {len(code_files)} code files...[/cyan]")

    # Prepare code for LLM analysis
    code_snippets = []
    for f in code_files[:10]:  # Limit for analysis
        try:
            content = f.read_text()
            code_snippets.append(f"=== {f.relative_to(target)} ===\n{content[:3000]}")
        except:
            pass

    code_text = "\n\n".join(code_snippets)

    analysis_prompt = f"""You are a smart contract security expert conducting an audit.

Program: {context["program_description"]}
Scope: {context["scope"]}
Guidelines: {context["guidelines"]}

Analyze the following code for security vulnerabilities:

{code_text}

Provide your analysis in JSON format:
{{
  "summary": "Brief summary of the codebase",
  "high_risk_areas": ["area1", "area2"],
  "potential_vulnerabilities": [
    {{
      "severity": "High/Medium/Low",
      "category": "Reentrancy/AccessControl/etc",
      "location": "file path",
      "description": "Description of the issue"
    }}
  ],
  "recommendations": ["rec1", "rec2"]
}}"""

    try:
        result = await brain.llm_client.analyze(analysis_prompt, max_tokens=4000)

        # Try to parse JSON
        try:
            analysis = json.loads(result)
            analysis_file = output / "llm-analysis.json"
            analysis_file.write_text(json.dumps(analysis, indent=2))
            console.print(f"[green]✓ LLM analysis complete[/green]")

            if "potential_vulnerabilities" in analysis:
                vuln_count = len(analysis["potential_vulnerabilities"])
                console.print(f"  • Found {vuln_count} potential issues")
        except:
            analysis_file = output / "llm-analysis.txt"
            analysis_file.write_text(result)
            console.print(f"[yellow]LLM analysis saved (raw format)[/yellow]")
    except Exception as e:
        console.print(f"[yellow]LLM analysis failed: {e}[/yellow]")


async def _run_scanners(target: Path, output: Path):
    """Run security scanners."""
    from vulnhunter.core.sarif_merger import SarifMerger
    from vulnhunter.core.deduplicator import Deduplicator
    from vulnhunter.adapters.mock_scanner_adapter import MockScannerAdapter

    merger = SarifMerger()
    deduplicator = Deduplicator()

    # Try to run available scanners
    scanner_results = []

    # Check for slither
    try:
        import subprocess

        result = subprocess.run(
            ["slither", str(target), "--json", "-", "--exclude-dependencies"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0 or result.stdout:
            try:
                findings = json.loads(result.stdout)
                console.print("[green]✓ Slither scan complete[/green]")
                scanner_results.append(findings)
            except:
                console.print("[yellow]⚠ Slither found issues but output parsing failed[/yellow]")
    except Exception as e:
        console.print(f"[yellow]⚠ Slither not available: {e}[/yellow]")

    # Run mock scanner as fallback for testing
    if not scanner_results:
        console.print("[cyan]Running mock scanner for testing...[/cyan]")
        adapter = MockScannerAdapter()
        findings = await adapter.run(str(target))
        scanner_results.append(findings)

    # Merge and deduplicate
    if scanner_results:
        merged = merger.merge_findings(scanner_results)
        unique = deduplicator.deduplicate(merged)

        # Save findings
        findings_file = output / "findings.json"
        with open(findings_file, "w") as f:
            json.dump([f.dict() if hasattr(f, "dict") else f for f in unique], f, indent=2)

        console.print(f"[green]✓ Scan complete: {len(unique)} unique findings[/green]")
    else:
        console.print("[yellow]⚠ No scanner results available[/yellow]")


async def _deploy_local(target: Path, output: Path):
    """Attempt to build/deploy project locally."""
    import subprocess

    deploy_status = {"success": False, "steps": []}

    # Detect project type and try to build
    if (target / "foundry.toml").exists():
        console.print("[cyan]Detected Foundry project, attempting to build...[/cyan]")
        try:
            result = subprocess.run(
                ["forge", "build"], cwd=target, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0:
                deploy_status["success"] = True
                deploy_status["steps"].append("Forge build: SUCCESS")
                console.print("[green]✓ Foundry build successful[/green]")
            else:
                deploy_status["steps"].append(f"Forge build: FAILED - {result.stderr[:200]}")
                console.print("[yellow]⚠ Foundry build failed[/yellow]")
        except Exception as e:
            deploy_status["steps"].append(f"Forge build: ERROR - {e}")
            console.print(f"[yellow]⚠ Build error: {e}[/yellow]")

    elif (target / "Cargo.toml").exists():
        console.print("[cyan]Detected Rust project, attempting to build...[/cyan]")
        try:
            result = subprocess.run(
                ["cargo", "build"], cwd=target, capture_output=True, text=True, timeout=180
            )
            if result.returncode == 0:
                deploy_status["success"] = True
                deploy_status["steps"].append("Cargo build: SUCCESS")
                console.print("[green]✓ Rust build successful[/green]")
            else:
                deploy_status["steps"].append(f"Cargo build: FAILED")
                console.print("[yellow]⚠ Rust build failed[/yellow]")
        except Exception as e:
            deploy_status["steps"].append(f"Cargo build: ERROR - {e}")
            console.print(f"[yellow]⚠ Build error: {e}[/yellow]")

    else:
        console.print("[yellow]⚠ Unknown project type, skipping build[/yellow]")
        deploy_status["steps"].append("Unknown project type")

    # Save deploy status
    deploy_file = output / "deploy-status.json"
    deploy_file.write_text(json.dumps(deploy_status, indent=2))


async def _generate_pocs(target: Path, output: Path):
    """Generate PoC exploits for findings."""
    try:
        generator = PoCGenerator()

        findings_file = output / "findings.json"
        if not findings_file.exists():
            console.print("[yellow]No findings to generate PoCs for[/yellow]")
            return

        findings = json.loads(findings_file.read_text())

        pocs_generated = 0
        for finding in findings:
            # Only generate PoCs for medium+ severity
            severity = finding.get("severity", "").lower()
            if severity in ["high", "critical", "medium"]:
                try:
                    poc_code = generator.generate(finding)
                    if poc_code:
                        poc_file = output / f"poc_{finding.get('id', pocs_generated)}.t.sol"
                        poc_file.write_text(poc_code)
                        pocs_generated += 1
                except Exception as e:
                    console.print(f"[yellow]Failed to generate PoC: {e}[/yellow]")

        console.print(f"[green]✓ Generated {pocs_generated} PoC files[/green]")
    except Exception as e:
        console.print(f"[yellow]PoC generation failed: {e}[/yellow]")


def _generate_report(output: Path, context: dict):
    """Generate final audit report."""

    # Load all results
    report_sections = []

    report_sections.append(f"# Security Audit Report\n")
    report_sections.append(f"## Program Information\n")
    report_sections.append(f"- **Repository**: {context['repo_url']}")
    report_sections.append(f"- **Scope**: {context['scope']}")
    report_sections.append(f"- **Description**: {context['program_description']}")
    report_sections.append(f"- **Reward Pool**: {context['reward_pool']}\n")

    # Add recon summary
    recon_file = output / "recon-report.json"
    if recon_file.exists():
        recon = json.loads(recon_file.read_text())
        report_sections.append(f"## Reconnaissance Summary\n")
        report_sections.append(f"- **Ecosystems**: {', '.join(recon.get('ecosystems', []))}")
        report_sections.append(f"- **Build Status**: {recon.get('build_status', 'Unknown')}")
        report_sections.append(f"- **Total LOC**: {recon.get('total_loc', 0):,}")
        report_sections.append(f"- **Hot Zones**: {len(recon.get('hot_zones', []))}\n")

    # Add findings
    findings_file = output / "findings.json"
    if findings_file.exists():
        findings = json.loads(findings_file.read_text())
        report_sections.append(f"## Findings ({len(findings)})\n")

        for i, finding in enumerate(findings, 1):
            report_sections.append(f"### Finding {i}: {finding.get('title', 'Unknown')}\n")
            report_sections.append(f"- **Severity**: {finding.get('severity', 'Unknown')}")
            report_sections.append(f"- **Category**: {finding.get('rule_id', 'Unknown')}")
            if finding.get("location"):
                loc = finding["location"]
                report_sections.append(
                    f"- **Location**: {loc.get('file', 'Unknown')}:{loc.get('start_line', 'N/A')}"
                )
            report_sections.append(f"- **Description**: {finding.get('description', 'N/A')}\n")

    # Add LLM analysis
    analysis_file = output / "llm-analysis.json"
    if analysis_file.exists():
        analysis = json.loads(analysis_file.read_text())
        report_sections.append(f"## LLM Analysis\n")
        report_sections.append(f"{analysis.get('summary', 'N/A')}\n")

        if analysis.get("recommendations"):
            report_sections.append(f"### Recommendations\n")
            for rec in analysis["recommendations"]:
                report_sections.append(f"- {rec}")
            report_sections.append("")

    # Write report
    report_file = output / "AUDIT-REPORT.md"
    report_file.write_text("\n".join(report_sections))

    console.print(f"[green]✓ Report saved: {report_file}[/green]")

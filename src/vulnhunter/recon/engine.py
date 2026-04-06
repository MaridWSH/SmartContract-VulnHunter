"""Reconnaissance engine - orchestrates 10-phase reconnaissance."""

from __future__ import annotations

import asyncio
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnhunter.recon.models.recon_report import (
    ContractInfo,
    FileChangeInfo,
    HotZone,
    ReconReport,
    TodoItem,
)

console = Console()


class ReconEngine:
    """Orchestrates 10-phase reconnaissance on a target codebase."""

    def __init__(self, target_path: str, repo_url: Optional[str] = None):
        self.target_path = Path(target_path)
        self.repo_url = repo_url or self._detect_repo_url()
        self.report = ReconReport(
            repo_url=self.repo_url or str(self.target_path),
            target_path=str(self.target_path),
            repo_name=self.target_path.name,
            commit_hash=self._get_commit_hash(),
            commit_message=self._get_commit_message(),
        )

    def _detect_repo_url(self) -> Optional[str]:
        """Try to detect the repo URL from git config."""
        try:
            result = subprocess.run(
                ["git", "-C", str(self.target_path), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None

    def _get_commit_hash(self) -> str:
        """Get current commit hash."""
        try:
            result = subprocess.run(
                ["git", "-C", str(self.target_path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "unknown"

    def _get_commit_message(self) -> str:
        """Get current commit message."""
        try:
            result = subprocess.run(
                ["git", "-C", str(self.target_path), "log", "-1", "--pretty=%B"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return "unknown"

    async def run_recon(self, phases: Optional[List[str]] = None) -> ReconReport:
        """Run full or partial reconnaissance.

        Args:
            phases: List of phase names to run, or None for all phases

        Returns:
            Complete reconnaissance report
        """
        all_phases = [
            ("target-acquisition", self._phase_1_target_acquisition),
            ("build-verification", self._phase_2_build_verification),
            ("codebase-mapping", self._phase_3_codebase_mapping),
            ("architecture", self._phase_4_architecture),
            ("attack-surface", self._phase_5_attack_surface),
            ("test-coverage", self._phase_6_test_coverage),
            ("dependencies", self._phase_7_dependencies),
            ("git-history", self._phase_8_git_history),
            ("prior-audits", self._phase_9_prior_audits),
            ("report-generation", self._phase_10_report_generation),
        ]

        if phases:
            # Filter to only requested phases
            all_phases = [(name, fn) for name, fn in all_phases if name in phases]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for phase_name, phase_fn in all_phases:
                task = progress.add_task(f"Running {phase_name}...", total=None)
                try:
                    await phase_fn()
                except Exception as e:
                    console.print(f"[yellow]⚠️  Phase {phase_name} failed: {e}[/yellow]")
                progress.update(task, completed=True)

        return self.report

    async def _phase_1_target_acquisition(self) -> None:
        """Phase 1: Detect ecosystem and collect metadata."""
        console.print("[blue]Phase 1: Target Acquisition[/blue]")

        # Detect ecosystems
        ecosystems = []

        # Check for Solidity
        if (
            (self.target_path / "foundry.toml").exists()
            or (self.target_path / "hardhat.config.js").exists()
            or (self.target_path / "hardhat.config.ts").exists()
        ):
            ecosystems.append("solidity")

        # Check for Vyper
        if list(self.target_path.glob("**/*.vy")):
            ecosystems.append("vyper")

        # Check for Rust/Solana
        if (self.target_path / "Anchor.toml").exists() or (
            self.target_path / "Cargo.toml"
        ).exists():
            ecosystems.append("rust")

        # Check for Cairo
        if (self.target_path / "Scarb.toml").exists():
            ecosystems.append("cairo")

        self.report.ecosystems = ecosystems
        console.print(f"  Detected ecosystems: {', '.join(ecosystems)}")

    async def _phase_2_build_verification(self) -> None:
        """Phase 2: Verify the codebase builds successfully."""
        console.print("[blue]Phase 2: Build Verification[/blue]")

        build_errors = []
        framework = None

        # Try Foundry
        if (self.target_path / "foundry.toml").exists():
            framework = "foundry"
            try:
                result = subprocess.run(
                    ["forge", "build"],
                    cwd=self.target_path,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    self.report.build_status = "PASS"
                    # Extract compiler version
                    pragma_output = subprocess.run(
                        ["grep", "-r", "pragma solidity", "--include=*.sol", "src/"],
                        cwd=self.target_path,
                        capture_output=True,
                        text=True,
                    )
                    if pragma_output.stdout:
                        # Parse first pragma line
                        first_pragma = pragma_output.stdout.strip().split("\n")[0]
                        if "0." in first_pragma:
                            version = first_pragma.split("0.")[1].split()[0]
                            self.report.compiler_versions["solc"] = f"0.{version}"
                else:
                    build_errors.append(result.stderr)
                    self.report.build_status = "FAIL"
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                build_errors.append(str(e))
                self.report.build_status = "FAIL"

        # Try Hardhat
        elif (self.target_path / "hardhat.config.js").exists() or (
            self.target_path / "hardhat.config.ts"
        ).exists():
            framework = "hardhat"
            try:
                result = subprocess.run(
                    ["npx", "hardhat", "compile"],
                    cwd=self.target_path,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                self.report.build_status = "PASS" if result.returncode == 0 else "FAIL"
                if result.returncode != 0:
                    build_errors.append(result.stderr[:500])
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                build_errors.append(str(e))
                self.report.build_status = "FAIL"

        # Try Anchor (Solana)
        elif (self.target_path / "Anchor.toml").exists():
            framework = "anchor"
            try:
                result = subprocess.run(
                    ["anchor", "build"],
                    cwd=self.target_path,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                self.report.build_status = "PASS" if result.returncode == 0 else "FAIL"
                if result.returncode != 0:
                    build_errors.append(result.stderr[:500])
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                build_errors.append(str(e))
                self.report.build_status = "FAIL"

        # Try Scarb (Cairo)
        elif (self.target_path / "Scarb.toml").exists():
            framework = "scarb"
            try:
                result = subprocess.run(
                    ["scarb", "build"],
                    cwd=self.target_path,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                self.report.build_status = "PASS" if result.returncode == 0 else "FAIL"
                if result.returncode != 0:
                    build_errors.append(result.stderr[:500])
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                build_errors.append(str(e))
                self.report.build_status = "FAIL"

        else:
            self.report.build_status = "PARTIAL"
            build_errors.append("No recognized build system found")

        self.report.framework = framework
        self.report.build_errors = build_errors
        console.print(f"  Build status: {self.report.build_status}")

    async def _phase_3_codebase_mapping(self) -> None:
        """Phase 3: Map the codebase structure."""
        console.print("[blue]Phase 3: Codebase Mapping[/blue]")

        # Count files by type
        solidity_files = list(self.target_path.glob("**/*.sol"))
        rust_files = list(self.target_path.glob("**/*.rs"))
        vyper_files = list(self.target_path.glob("**/*.vy"))
        cairo_files = list(self.target_path.glob("**/*.cairo"))

        # Try to get LOC
        total_loc = 0
        try:
            # Count lines in source files
            all_source_files = solidity_files + rust_files + vyper_files + cairo_files
            for f in all_source_files[:100]:  # Limit to avoid hanging
                try:
                    total_loc += len(f.read_text().splitlines())
                except:
                    pass
        except:
            pass

        self.report.total_loc = total_loc

        # Determine scope (src/ directory or similar)
        scope_dirs = ["src", "contracts", "programs"]
        in_scope = []
        for scope_dir in scope_dirs:
            dir_path = self.target_path / scope_dir
            if dir_path.exists():
                in_scope.extend(
                    [
                        str(f.relative_to(self.target_path))
                        for f in dir_path.glob("**/*")
                        if f.is_file()
                    ]
                )

        self.report.in_scope_files = in_scope[:100]  # Limit
        console.print(f"  Total LOC: {total_loc:,}")
        console.print(f"  In-scope files: {len(in_scope)}")

    async def _phase_4_architecture(self) -> None:
        """Phase 4: Understand protocol architecture."""
        console.print("[blue]Phase 4: Architecture Analysis[/blue]")

        # Simple protocol type detection based on file names and greps
        protocol_indicators = {
            "lending": ["lend", "borrow", "interest", "apy", "debt", "collateral"],
            "dex": ["swap", "amm", "pool", "liquidity", "trade", "exchange"],
            "vault": ["vault", "yield", "strategy", "deposit", "withdraw"],
            "bridge": ["bridge", "cross-chain", "relay", "messaging"],
            "governance": ["govern", "vote", "proposal", "timelock", "dao"],
            "oracle": ["oracle", "price", "feed", "aggregator"],
            "nft": ["nft", "erc721", "erc1155", "marketplace"],
            "staking": ["stake", "reward", "validator", "epoch"],
        }

        # Check file names
        all_files = list(self.target_path.rglob("*"))
        file_names = [f.name.lower() for f in all_files if f.is_file()]

        scores = {ptype: 0 for ptype in protocol_indicators}
        for ptype, indicators in protocol_indicators.items():
            for indicator in indicators:
                for fname in file_names:
                    if indicator in fname:
                        scores[ptype] += 1

        # Pick highest scoring
        if scores:
            best_match = max(scores, key=scores.get)
            if scores[best_match] > 0:
                self.report.protocol_type = best_match
                console.print(f"  Detected protocol type: {best_match}")

    async def _phase_5_attack_surface(self) -> None:
        """Phase 5: Enumerate attack surface."""
        console.print("[blue]Phase 5: Attack Surface Enumeration[/blue]")

        # Grep for attack surface indicators
        attack_patterns = {
            "external_call_sites": r"\.call\{|\.delegatecall\{|\.staticcall\{",
            "payable_functions": r"function\s+\w+\s*\([^)]*\)\s+(?:external\s+|public\s+)*payable",
            "oracle_dependencies": r"oracle|price.*feed|getPrice|latestRoundData",
            "assembly_blocks": r"assembly\s*\{",
            "unchecked_blocks": r"unchecked\s*\{",
            "signature_operations": r"ecrecover|verify.*sig|signature",
            "delegatecall_sites": r"delegatecall",
        }

        results = {}
        for pattern_name, pattern in attack_patterns.items():
            try:
                result = subprocess.run(
                    ["grep", "-r", "-i", "-E", pattern, "--include=*.sol", "src/"],
                    cwd=self.target_path,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                count = len([line for line in result.stdout.split("\n") if line.strip()])
                results[pattern_name] = count
            except:
                results[pattern_name] = 0

        self.report.external_call_sites = results.get("external_call_sites", 0)
        self.report.payable_functions = results.get("payable_functions", 0)
        self.report.oracle_dependencies = results.get("oracle_dependencies", 0)
        self.report.assembly_blocks = results.get("assembly_blocks", 0)
        self.report.unchecked_blocks = results.get("unchecked_blocks", 0)
        self.report.signature_operations = results.get("signature_operations", 0)
        self.report.delegatecall_sites = results.get("delegatecall_sites", 0)

        # Create hot zones based on attack surface
        hot_zones = []
        if self.report.oracle_dependencies > 0:
            hot_zones.append(
                HotZone(
                    file_path="oracle-integration",
                    reason=f"{self.report.oracle_dependencies} oracle dependencies detected",
                    risk_score=8,
                    attack_vectors=["price manipulation", "stale price", "oracle delay"],
                )
            )

        if self.report.external_call_sites > 5:
            hot_zones.append(
                HotZone(
                    file_path="external-calls",
                    reason=f"{self.report.external_call_sites} external call sites",
                    risk_score=9,
                    attack_vectors=["reentrancy", "callback manipulation"],
                )
            )

        self.report.hot_zones = hot_zones
        console.print(f"  External calls: {self.report.external_call_sites}")
        console.print(f"  Oracle deps: {self.report.oracle_dependencies}")
        console.print(f"  Hot zones identified: {len(hot_zones)}")

    async def _phase_6_test_coverage(self) -> None:
        """Phase 6: Analyze test coverage."""
        console.print("[blue]Phase 6: Test Coverage Analysis[/blue]")

        # Try to run forge coverage
        if self.report.framework == "foundry":
            try:
                result = subprocess.run(
                    ["forge", "coverage", "--report", "summary"],
                    cwd=self.target_path,
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                # Parse coverage output
                if "%" in result.stdout:
                    for line in result.stdout.split("\n"):
                        if "%" in line and "total" in line.lower():
                            try:
                                pct = float(line.split("%")[0].split()[-1])
                                self.report.test_coverage_percent = pct
                            except:
                                pass
            except:
                pass

        console.print(f"  Test coverage: {self.report.test_coverage_percent or 'Unknown'}%")

    async def _phase_7_dependencies(self) -> None:
        """Phase 7: Audit dependencies."""
        console.print("[blue]Phase 7: Dependency Audit[/blue]")

        # Try cargo audit for Rust
        if "rust" in self.report.ecosystems:
            try:
                result = subprocess.run(
                    ["cargo", "audit", "--json"],
                    cwd=self.target_path,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.stdout:
                    try:
                        audit_data = json.loads(result.stdout)
                        vulnerabilities = audit_data.get("vulnerabilities", {}).get("list", [])
                        self.report.cargo_audit_results = [
                            v.get("advisory", {}).get("title", "Unknown") for v in vulnerabilities
                        ]
                        self.report.known_vulnerable_deps.extend(self.report.cargo_audit_results)
                    except:
                        pass
            except:
                pass

        console.print(f"  Vulnerable deps: {len(self.report.known_vulnerable_deps)}")

    async def _phase_8_git_history(self) -> None:
        """Phase 8: Analyze git history."""
        console.print("[blue]Phase 8: Git History Analysis[/blue]")

        # Get recent commits
        try:
            result = subprocess.run(
                ["git", "log", "--oneline", "-20", "--pretty=format:%H|%s|%an|%ad", "--date=short"],
                cwd=self.target_path,
                capture_output=True,
                text=True,
                check=True,
            )

            recent_changes = []
            for line in result.stdout.strip().split("\n"):
                parts = line.split("|", 3)
                if len(parts) == 4:
                    recent_changes.append(
                        FileChangeInfo(
                            file_path="multiple",
                            commit_hash=parts[0][:8],
                            commit_message=parts[1],
                            author=parts[2],
                            date=datetime.strptime(parts[3], "%Y-%m-%d"),
                            lines_changed=0,
                        )
                    )

            self.report.recently_changed_files = recent_changes[:10]
            console.print(f"  Recent commits analyzed: {len(recent_changes)}")
        except:
            pass

        # Check for security-related commits
        try:
            result = subprocess.run(
                [
                    "git",
                    "log",
                    "--oneline",
                    "--all",
                    "--grep=security\\|fix\\|patch\\|vuln",
                    "-i",
                    "-10",
                ],
                cwd=self.target_path,
                capture_output=True,
                text=True,
            )
            if result.stdout:
                console.print(
                    f"  Security-related commits: {len(result.stdout.strip().split(chr(10)))}"
                )
        except:
            pass

    async def _phase_9_prior_audits(self) -> None:
        """Phase 9: Check for prior audits."""
        console.print("[blue]Phase 9: Prior Audit Check[/blue]")

        # Look for audit files
        audit_patterns = ["*audit*", "*security*", "*review*"]
        audit_files = []

        for pattern in audit_patterns:
            audit_files.extend(self.target_path.glob(f"**/{pattern}.md"))
            audit_files.extend(self.target_path.glob(f"**/{pattern}.pdf"))

        if audit_files:
            console.print(f"  Prior audit reports found: {len(audit_files)}")
            for f in audit_files[:3]:
                console.print(f"    - {f.name}")

        # Check for SECURITY.md
        security_md = self.target_path / "SECURITY.md"
        if security_md.exists():
            console.print("  SECURITY.md present")

    async def _phase_10_report_generation(self) -> None:
        """Phase 10: Finalize report."""
        console.print("[blue]Phase 10: Report Generation[/blue]")

        # Summary stats
        console.print(f"\n[green]Recon Complete![/green]")
        console.print(f"  Ecosystems: {', '.join(self.report.ecosystems)}")
        console.print(f"  Build: {self.report.build_status}")
        console.print(f"  LOC: {self.report.total_loc:,}")
        console.print(f"  Hot Zones: {len(self.report.hot_zones)}")

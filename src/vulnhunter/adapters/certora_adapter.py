"""Certora Prover adapter for formal verification.

Certora is the gold standard for smart contract formal verification.
This adapter invokes certoraRun and parses counterexamples.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from vulnhunter.models.finding import Finding, FindingSeverity, SourceLocation

logger = logging.getLogger(__name__)


class CertoraAdapter:
    """Adapter for Certora Prover formal verification.

    Requires: certora-cli (pip install certora-cli)
    """

    name = "certora"

    def __init__(self, timeout: int = 1800):
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            result = subprocess.run(
                ["certoraRun", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def run(
        self,
        spec_file: Path,
        contract_file: Path,
        contract_name: str,
        config: Optional[Dict] = None,
    ) -> List[Finding]:
        """Run Certora Prover on a contract against a spec file.

        Args:
            spec_file: Path to the .spec CVL file
            contract_file: Path to the Solidity contract
            contract_name: Name of the contract to verify
            config: Optional Certora config overrides

        Returns:
            List of Findings for each violated rule
        """
        if not self.is_available():
            logger.warning("Certora not available; skipping formal verification")
            return []

        findings = []

        try:
            cmd = [
                "certoraRun",
                str(contract_file),
                "--verify",
                f"{contract_name}:{spec_file}",
                "--rule_sanity",
                "--send_only",
                "--optimistic_loop",
                f"--prover_args", "-solverTimeout {timeout}",
            ]

            if config:
                if "solc" in config:
                    cmd.extend(["--solc", config["solc"]])
                if "optimistic_loop" in config:
                    cmd.append("--optimistic_loop" if config["optimistic_loop"] else "")

            logger.info(f"Running Certora: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )

            # Parse output for violations
            findings.extend(self._parse_output(result.stdout, result.stderr, contract_file))

        except subprocess.TimeoutExpired:
            logger.warning(f"Certora timed out after {self.timeout}s")
        except Exception as exc:
            logger.warning(f"Certora run failed: {exc}")

        return findings

    def _parse_output(
        self, stdout: str, stderr: str, contract_file: Path
    ) -> List[Finding]:
        """Parse Certora output for rule violations."""
        findings = []
        combined = stdout + "\n" + stderr

        # Look for violated rules
        # Certora output format:
        # [RULE] <rule_name> - <status>
        # Violated rules appear with counterexamples
        lines = combined.splitlines()
        current_rule = None

        for line in lines:
            line = line.strip()

            # Detect rule name
            if line.startswith("Rule ") and "is " in line:
                parts = line.split("is ")
                if len(parts) == 2:
                    current_rule = parts[0].replace("Rule ", "").strip()
                    status = parts[1].strip().rstrip(".")

                    if status.lower() in ("violated", "false"):
                        # This rule was violated
                        findings.append(
                            Finding(
                                tool="certora",
                                rule_id=f"certora_{current_rule}",
                                severity=FindingSeverity.CRITICAL,
                                confidence="high",
                                title=f"Certora: Invariant '{current_rule}' violated",
                                description=(
                                    f"Formal verification found a counterexample "
                                    f"to the invariant '{current_rule}'. "
                                    f"This is a mathematically proven violation."
                                ),
                                location=SourceLocation(
                                    file=str(contract_file), start_line=1
                                ),
                            )
                        )

        return findings

    def check_spec_syntax(self, spec_file: Path) -> tuple[bool, str]:
        """Check if a CVL spec file is syntactically valid.

        Returns:
            (is_valid, error_message)
        """
        if not self.is_available():
            return False, "Certora not installed"

        try:
            result = subprocess.run(
                ["certoraRun", "--check-spec", str(spec_file)],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode == 0:
                return True, ""
            else:
                return False, result.stderr or result.stdout

        except Exception as exc:
            return False, str(exc)

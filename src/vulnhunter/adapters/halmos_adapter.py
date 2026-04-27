"""Halmos adapter for formal verification via symbolic execution.

Runs `halmos --contract <ContractName>` against Foundry projects
and parses counterexamples into Finding objects.
"""

from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from pathlib import Path
from typing import List, Optional

from vulnhunter.adapters.base import ToolAdapter
from vulnhunter.models import Finding, FindingSeverity, FindingConfidence, SourceLocation

logger = logging.getLogger(__name__)


class HalmosAdapter(ToolAdapter):
    """Halmos symbolic execution adapter."""

    name = "halmos"

    def is_available(self) -> bool:
        try:
            subprocess.run(
                ["halmos", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            return True
        except Exception:
            return False

    async def run(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        p = Path(target)
        if not (p / "foundry.toml").exists():
            logger.warning(f"Halmos requires a Foundry project; {target} has no foundry.toml")
            return findings

        cmd = [
            "halmos",
            "--root", str(p),
            "--contract", "*",
            "--timeout", "300",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=360)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("Halmos timed out after 360s")
            return findings
        except Exception as exc:
            logger.warning(f"Halmos execution failed: {exc}")
            return findings

        text = (stdout or b"").decode(errors="ignore")
        findings.extend(self._parse_output(text, target))
        return findings

    def _parse_output(self, text: str, target: str) -> List[Finding]:
        findings: List[Finding] = []

        # Halmos counterexample format:
        # Counterexample: ...
        #   src/Vault.sol:42
        counter_pattern = re.compile(
            r"Counterexample.*?\n.*?src/(.*?):(\d+)",
            re.IGNORECASE | re.DOTALL,
        )
        for m in counter_pattern.finditer(text):
            file_path = f"{target}/src/{m.group(1)}"
            line = int(m.group(2))
            finding = Finding(
                tool=self.name,
                rule_id="halmos.counterexample",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.HIGH,
                title="Halmos counterexample found",
                description="Halmos found a counterexample violating a property test.",
                location=SourceLocation(file=file_path, start_line=line),
            )
            finding.compute_fingerprint()
            findings.append(finding)

        # Also look for assertion failures
        assert_pattern = re.compile(
            r"assertion failed.*?(\S+\.sol):(\d+)",
            re.IGNORECASE,
        )
        for m in assert_pattern.finditer(text):
            file_path = f"{target}/{m.group(1)}"
            line = int(m.group(2))
            finding = Finding(
                tool=self.name,
                rule_id="halmos.assertion_failed",
                severity=FindingSeverity.CRITICAL,
                confidence=FindingConfidence.HIGH,
                title="Halmos assertion failure",
                description="Property test assertion failed under symbolic execution.",
                location=SourceLocation(file=file_path, start_line=line),
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings

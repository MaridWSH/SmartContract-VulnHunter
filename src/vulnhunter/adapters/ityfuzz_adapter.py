"""ItyFuzz adapter — hybrid fuzzer (symbolic + greybox)."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import subprocess
from pathlib import Path
from typing import List, Optional

from vulnhunter.adapters.base import ToolAdapter
from vulnhunter.models import Finding, FindingSeverity, FindingConfidence, SourceLocation

logger = logging.getLogger(__name__)


class ItyFuzzAdapter(ToolAdapter):
    """ItyFuzz EVM fuzzer adapter."""

    name = "ityfuzz"

    def is_available(self) -> bool:
        try:
            subprocess.run(
                ["ityfuzz", "--version"],
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

        # Detect if DeFi protocol for flashloan flag
        is_defi = self._is_defi_protocol(p)
        flags = ["evm", "-t", str(p), "-f"]
        if is_defi:
            flags.append("--flashloan")

        cmd = ["ityfuzz"] + flags
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("ItyFuzz timed out after 600s")
            return findings
        except Exception as exc:
            logger.warning(f"ItyFuzz execution failed: {exc}")
            return findings

        text = (stdout or b"").decode(errors="ignore")
        findings.extend(self._parse_output(text, target))
        return findings

    def _parse_output(self, text: str, target: str) -> List[Finding]:
        findings: List[Finding] = []

        # ItyFuzz crash pattern
        crash_pattern = re.compile(
            r"Crash.*?contract:\s*(\S+).*?function:\s*(\S+).*?line:\s*(\d+)",
            re.IGNORECASE | re.DOTALL,
        )
        for m in crash_pattern.finditer(text):
            contract = m.group(1)
            func = m.group(2)
            line = int(m.group(3))
            finding = Finding(
                tool=self.name,
                rule_id="ityfuzz.crash",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.MEDIUM,
                title=f"ItyFuzz crash in {contract}.{func}",
                description=f"ItyFuzz found a crash in {contract}.{func}.",
                location=SourceLocation(file=f"{target}/{contract}.sol", start_line=line),
            )
            finding.compute_fingerprint()
            findings.append(finding)

        # Invariant violation pattern
        inv_pattern = re.compile(
            r"Invariant violation.*?contract:\s*(\S+).*?line:\s*(\d+)",
            re.IGNORECASE | re.DOTALL,
        )
        for m in inv_pattern.finditer(text):
            contract = m.group(1)
            line = int(m.group(2))
            finding = Finding(
                tool=self.name,
                rule_id="ityfuzz.invariant",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.MEDIUM,
                title=f"ItyFuzz invariant violation in {contract}",
                description="ItyFuzz found an invariant violation.",
                location=SourceLocation(file=f"{target}/{contract}.sol", start_line=line),
            )
            finding.compute_fingerprint()
            findings.append(finding)

        return findings

    def _is_defi_protocol(self, path: Path) -> bool:
        """Heuristic: check if project looks like DeFi."""
        source = path / "src"
        if not source.exists():
            return False
        text = ""
        for fp in list(source.rglob("*.sol"))[:10]:
            try:
                text += fp.read_text().lower()
            except Exception:
                pass
        indicators = ["flashloan", "pool", "vault", "amm", "swap", "liquidity", "lend"]
        return any(ind in text for ind in indicators)

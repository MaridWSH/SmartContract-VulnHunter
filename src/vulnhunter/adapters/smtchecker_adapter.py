"""SMTChecker adapter for VulnHunter - integrates SMT solver warnings via CHC output."""

from __future__ import annotations

import asyncio
import re
import subprocess
import logging
from pathlib import Path
from typing import List

from vulnhunter.adapters.base import ToolAdapter
from vulnhunter.models import (
    Finding,
    FindingSeverity,
    FindingConfidence,
    SourceLocation,
)

logger = logging.getLogger(__name__)


class SMTCheckerAdapter(ToolAdapter):
    """Adapter that runs SMTChecker (solc --model-checker-engine) and parses CHC warnings
    emitted to stderr. Translates to VulnHunter Finding model."""

    name = "smtchecker"

    def is_available(self) -> bool:
        """Return True if solc is available and version >= 0.8.0."""
        try:
            res = subprocess.run(
                ["solc", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            output = (res.stdout or "") + (res.stderr or "")
            m = re.search(r"(\d+)\.(\d+)\.(\d+)", output)
            if not m:
                return False
            maj, minr, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            # Accept 0.8.x and above
            if maj > 0 or (maj == 0 and minr >= 8):
                return True
            return False
        except Exception:
            return False

    async def run(self, target: str) -> List[Finding]:
        """Run SMTChecker on all .sol files under target and parse CHC warnings from stderr."""
        findings: List[Finding] = []

        if not self.is_available():
            return findings

        # Gather .sol files
        paths = []
        p = Path(target)
        if p.is_dir():
            paths = sorted([str(p) for p in p.rglob("*.sol")])
        elif p.is_file() and p.suffix == ".sol":
            paths = [str(p)]
        else:
            return findings

        pattern = re.compile(
            r"Warning:\s*CHC:\s*(?P<desc>.+?)\n\s*--> (?P<file>.*?):(?P<line>\d+):(?P<col>\d+):?",
            re.IGNORECASE,
        )

        for sol_file in paths:
            cmd = [
                "solc",
                "--model-checker-engine",
                "all",
                "--model-checker-targets",
                "all",
                "--model-checker-timeout",
                "60000",
                sol_file,
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    continue
            except Exception as exc:
                logger.warning(f"SMTChecker: failed to run on {sol_file}: {exc}")
                continue

            err_text = (stderr or b"").decode(errors="ignore")
            for m in pattern.finditer(err_text):
                desc = m.group("desc").strip()
                file_path = m.group("file").strip()
                line = int(m.group("line"))
                col = m.group("col")
                start_col = int(col) if col is not None else None

                location = SourceLocation(
                    file=file_path, start_line=line, start_column=start_col
                )
                severity = self._severity_from_desc(desc)
                finding = Finding(
                    tool=self.name,
                    rule_id="smtchecker.chc",
                    severity=severity,
                    confidence=FindingConfidence.MEDIUM,
                    title=f"CHC: {desc}",
                    description=f"SMTChecker CHC: {desc}",
                    location=location,
                )
                if not getattr(finding, "fingerprint", None):
                    finding.compute_fingerprint()
                findings.append(finding)

        return findings

    def _severity_from_desc(self, desc: str) -> FindingSeverity:
        d = desc.lower()
        if "overflow" in d or "assertion" in d:
            return FindingSeverity.HIGH
        if "unreachable" in d:
            return FindingSeverity.LOW
        return FindingSeverity.MEDIUM

import asyncio
import json
import os
import shutil
from typing import List, Optional
import re

# Fallback Finding class if not available
try:
    from vulnhunter.findings import Finding
except Exception:
    from dataclasses import dataclass

    @dataclass
    class Finding:
        title: str
        severity: str
        description: str = ""
        evidence: str = ""
        location: Optional[str] = None


from .base import ToolAdapter  # type: ignore


class MedusaAdapter(ToolAdapter):
    name = "medusa"
    timeout_seconds = 600

    def __init__(self):
        super().__init__()

    def is_available(self) -> bool:
        return shutil.which("medusa") is not None

    async def run(self, target: str) -> List[Finding]:
        cmd = ["medusa", "fuzz", "--config", "medusa.json"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
            return [
                Finding(
                    title="Medusa fuzzing timed out",
                    severity="Medium",
                    description=f"Timeout after {self.timeout_seconds}s",
                )
            ]

        out_text = (stdout or b"").decode("utf-8", errors="replace")
        err_text = (stderr or b"").decode("utf-8", errors="replace")

        findings: List[Finding] = []

        # Heuristic parsing: look for common failure signals in the fuzzing output
        signals = []
        if out_text:
            for line in out_text.splitlines():
                if not line:
                    continue
                if re.search(r"(?i)fail|error|assert|exception", line):
                    signals.append(line)

        for line in signals:
            findings.append(
                Finding(
                    title="Medusa fuzzing failure",
                    severity="High",
                    description=line,
                    evidence=line,
                )
            )

        # If Medusa reports a coverage HTML, add a synthetic finding with location
        # Detect common coverage report filenames in the target directory
        coverage_paths = []
        for root, _, files in os.walk(target):
            for f in files:
                if f.lower().endswith(".html") and "coverage" in f.lower():
                    coverage_paths.append(os.path.join(root, f))
        if coverage_paths:
            for path in coverage_paths:
                findings.append(
                    Finding(
                        title="Medusa coverage report available",
                        severity="Info",
                        location=path,
                        description="HTML coverage report detected",
                    )
                )

        # Fallback: if nothing found, attempt to summarize stderr
        if not findings and err_text:
            findings.append(
                Finding(
                    title="Medusa fuzzing (unknown outcome)",
                    severity="Low",
                    description=err_text,
                )
            )

        return findings

from __future__ import annotations

import asyncio
import json
import shutil
import re
from typing import List

from .base import ToolAdapter
from vulnhunter.findings import Finding


class TridentAdapter(ToolAdapter):
    """Adapter for Solana fuzzing tool Trident.

    - name: trident
    - Command: trident fuzz run <target>
    - Output: textual fuzz results. Crashes are surfaced as Findings.
    - Supports Anchor programs by parsing common crash patterns.
    """

    name = "trident"

    def is_available(self) -> bool:
        return shutil.which("trident") is not None

    async def _collect_crashes(self, stdout: str) -> List[Finding]:
        findings: List[Finding] = []
        if not stdout:
            return findings

        # If Trident emits JSON blocks, try to parse them first
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and (
                        "crash" in item or " Crash" in str(item)
                    ):
                        findings.append(
                            Finding(
                                title="Trident crash",
                                description=str(item.get("crash"))
                                if isinstance(item, dict)
                                else str(item),
                                severity="High",
                                location=item.get("location")
                                if isinstance(item, dict)
                                else "target",
                                source=self.name,
                                raw=item,
                            )
                        )
        except json.JSONDecodeError:
            data = None

        if findings:
            return findings

        # Fallback: scan plain text for common crash indicators
        crash_lines = []
        for line in stdout.splitlines():
            if re.search(r"(?i)crash|panic|segfault|failed|exception", line):
                crash_lines.append(line.strip())
        for cl in crash_lines:
            findings.append(
                Finding(
                    title="Trident crash",
                    description=cl,
                    severity="High",
                    location="target",
                    source=self.name,
                    raw={"line": cl},
                )
            )
        return findings

    async def run(self, target: str) -> List[Finding]:
        """Run Trident fuzz on the given target and parse crashes."""
        findings: List[Finding] = []
        if not self.is_available():
            findings.append(
                Finding(
                    title="Trident unavailable",
                    description="trident tool not found in PATH",
                    severity="Low",
                    location=target,
                    source=self.name,
                    raw=None,
                )
            )
            return findings

        cmd = ["trident", "fuzz", "run", target]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return [
                Finding(
                    title=f"Trident fuzz timeout for {target}",
                    description=stderr.decode(errors="replace"),
                    severity="Medium",
                    location=target,
                    source=self.name,
                    raw=None,
                )
            ]

        out = (stdout or b"").decode(errors="replace")
        findings.extend(await self._collect_crashes(out))

        if not findings:
            findings.append(
                Finding(
                    title=f"Trident fuzz completed for {target}",
                    description="No crashes detected in fuzzing output.",
                    severity="Info",
                    location=target,
                    source=self.name,
                    raw=out,
                )
            )
        return findings

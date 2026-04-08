from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import List

from .base import ToolAdapter
from vulnhunter.models.finding import Finding


class HeimdallAdapter(ToolAdapter):
    """Adapter for Heimdall bytecode decompiler.

    - name: heimdall
    - Command: heimdall decompile <target>
    - Output: JSON with ABI and control flow when available. Falls back to raw output.
    - Handles both bytecode inputs and deployed contract addresses.
    """

    name = "heimdall"

    def is_available(self) -> bool:
        # Heimdall should be in PATH
        return shutil.which("heimdall") is not None

    async def _run_decompile(self, target: str) -> (str, str, int):
        # Execute the decompile command and return stdout, stderr, and exit code
        proc = await asyncio.create_subprocess_exec(
            "heimdall",
            "decompile",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "", "Process timeout", -1
        return (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
            proc.returncode,
        )

    async def run(self, target: str) -> List[Finding]:
        """Run Heimdall on the given target and map output to Finding objects."""
        findings: List[Finding] = []

        # Run decompile. The target may be a bytecode blob/file or a deployed address.
        stdout, stderr, code = await self._run_decompile(target)

        if code != 0:
            # Return a single finding describing the failure to decompile
            findings.append(
                Finding(
                    title=f"Heimdall decompile failed for target {target}",
                    description=stderr.strip() or "Unknown error during Heimdall decompile",
                    severity="High",
                    location=target,
                    source=self.name,
                    raw={"stdout": stdout, "stderr": stderr},
                )
            )
            return findings

        # Try to parse JSON output first
        data = None
        try:
            data = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            data = {"raw_output": stdout}

        # Heuristic extraction: look for common vulnerability-like entries
        try:
            if isinstance(data, dict):
                # Common keys that may contain vulnerability items
                for key in (
                    "vulnerabilities",
                    "issues",
                    "contracts",
                    "functions",
                    "abi",
                ):
                    if key in data:
                        items = data[key]
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict):
                                    title = (
                                        item.get("name")
                                        or item.get("title")
                                        or "Heimdall decompile item"
                                    )
                                    desc = (
                                        item.get("description")
                                        or item.get("note")
                                        or "Decompiled item from Heimdall"
                                    )
                                    sev = item.get("severity") or item.get("level") or "Info"
                                    loc = item.get("location") or target
                                    findings.append(
                                        Finding(
                                            title=f"Heimdall: {title}",
                                            description=desc,
                                            severity=str(sev),
                                            location=str(loc),
                                            source=self.name,
                                            raw=item,
                                        )
                                    )
                        break
        except Exception:
            # In case of any parsing issue, fall back to a generic finding
            findings.append(
                Finding(
                    title=f"Heimdall decompile output for {target}",
                    description="Unparsed Heimdall output; raw data preserved",
                    severity="Info",
                    location=target,
                    source=self.name,
                    raw=data,
                )
            )

        if not findings:
            findings.append(
                Finding(
                    title=f"Heimdall decompile: no structured findings for {target}",
                    description="Decompile produced no structured vulnerabilities.",
                    severity="Info",
                    location=target,
                    source=self.name,
                    raw=data,
                )
            )

        return findings

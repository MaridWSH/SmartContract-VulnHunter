"""Mythril adapter for VulnHunter - symbolic execution with aggressive timeouts."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from shutil import which
from typing import List, Any, Optional

from vulnhunter.adapters.base import ToolAdapter

try:
    from vulnhunter.models.finding import Finding, FindingSeverity
except Exception:
    Finding = Any
    FindingSeverity = Any


class MythrilAdapter(ToolAdapter):
    """Mythril adapter for symbolic execution with JSON output.

    Mythril is SLOW - can take minutes to hours. Uses aggressive timeout (300s default).
    """

    @property
    def name(self) -> str:
        return "mythril"

    def is_available(self) -> bool:
        """Return True if myth is installed and available on PATH."""
        return which("myth") is not None

    async def run(self, target: str, timeout: int = 300) -> List[Finding]:
        """Run mythril against the target and return a list of Findings.

        Command: myth analyze <target> -o json --execution-timeout <timeout>
        """
        if not self.is_available():
            return []

        # Check if this is a Foundry project
        target_path = Path(target)
        is_foundry = (target_path / "foundry.toml").exists()

        if is_foundry:
            cmd = f"myth foundry analyze {target} -o json --execution-timeout {timeout}"
        else:
            cmd = f"myth analyze {target} -o json --execution-timeout {timeout}"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            # Use longer timeout for subprocess than execution timeout
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout + 60
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return []

        if proc.returncode != 0 and not stdout:
            return []

        try:
            data = json.loads(stdout.decode("utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return []

        return self._parse_findings(data, target)

    def _parse_findings(self, data: Any, target: str) -> List[Finding]:
        """Parse mythril JSON output into Finding objects."""
        findings: List[Finding] = []

        issues = data.get("issues", []) if isinstance(data, dict) else []

        for issue in issues:
            if not isinstance(issue, dict):
                continue

            title = issue.get("title", "Unknown Issue")
            description = issue.get("description", "")
            severity = self._normalize_severity(issue.get("severity", ""))
            address = issue.get("address", "")
            code = issue.get("code", "")

            finding_data = {
                "tool": self.name,
                "rule_id": title.lower().replace(" ", "_"),
                "severity": severity,
                "confidence": "medium",
                "title": title,
                "description": description,
                "location": {
                    "file": target,
                    "start_line": 0,
                },
                "code_snippet": code,
                "metadata": {
                    "address": address,
                    "mythril_severity": issue.get("severity"),
                },
            }

            try:
                if Finding is not Any:
                    finding = Finding(**finding_data)
                else:
                    finding = self._create_fallback_finding(finding_data)
                findings.append(finding)
            except Exception:
                pass

        return findings

    def _normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize mythril severity to standard format."""
        if not severity:
            return "medium"

        severity = severity.lower()
        mapping = {
            "high": "high",
            "medium": "medium",
            "low": "low",
            "critical": "critical",
            "warning": "medium",
            "info": "low",
        }
        return mapping.get(severity, "medium")

    def _create_fallback_finding(self, data: dict) -> Any:
        """Create a lightweight finding object when Finding model unavailable."""

        class FallbackFinding:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)

        return FallbackFinding(**data)

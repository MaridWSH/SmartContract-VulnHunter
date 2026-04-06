"""Solhint adapter for SmartContract VulnHunter - linting for Solidity with JSON output."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from shutil import which
from typing import List, Any, Optional

from vulnhunter.adapters.base import ToolAdapter

try:
    from vulnhunter.models.finding import Finding, FindingSeverity, SourceLocation
except Exception:
    Finding = Any
    FindingSeverity = Any
    SourceLocation = Any


class SolhintAdapter(ToolAdapter):
    """Solhint adapter producing JSON output and translating to SmartContract VulnHunter Findings."""

    @property
    def name(self) -> str:
        return "solhint"

    def is_available(self) -> bool:
        """Return True if solhint is installed and available on PATH."""
        return which("solhint") is not None

    async def run(self, target: str) -> List[Finding]:
        """Run solhint against the target and return a list of Findings.

        Command built: solhint 'contracts/**/*.sol' -f json
        """
        if not self.is_available():
            return []

        # Check for custom config
        target_path = Path(target)
        config_arg = ""
        for config_name in [".solhint.json", ".solhint.json5"]:
            config_file = target_path / config_name
            if config_file.exists():
                config_arg = f" -c {config_file}"
                break

        # Build command with glob pattern
        cmd = f"solhint '{target}/contracts/**/*.sol' -f json{config_arg}"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
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
        """Parse solhint JSON output into Finding objects."""
        findings: List[Finding] = []

        if not isinstance(data, list):
            return findings

        for file_result in data:
            if not isinstance(file_result, dict):
                continue

            file_path = file_result.get("filePath", "")
            messages = file_result.get("messages", [])

            for msg in messages:
                if not isinstance(msg, dict):
                    continue

                severity = self._map_severity(msg.get("severity"))
                line = msg.get("line", 0)
                column = msg.get("column", 0)
                rule_id = msg.get("ruleId", "unknown")
                message = msg.get("message", "")

                finding_data = {
                    "tool": self.name,
                    "rule_id": rule_id,
                    "severity": severity,
                    "confidence": "medium",
                    "title": f"Solhint: {rule_id}",
                    "description": message,
                    "location": {
                        "file": file_path or target,
                        "start_line": line,
                        "start_column": column,
                    },
                    "metadata": {
                        "linter": "solhint",
                        "original_severity": msg.get("severity"),
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

    def _map_severity(self, severity: Optional[int]) -> str:
        """Map solhint severity to FindingSeverity.

        Solhint: 2 = error, 1 = warning
        """
        if severity == 2:
            return "high"
        elif severity == 1:
            return "medium"
        return "low"

    def _create_fallback_finding(self, data: dict) -> Any:
        """Create a lightweight finding object when Finding model unavailable."""

        class FallbackFinding:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)

        return FallbackFinding(**data)

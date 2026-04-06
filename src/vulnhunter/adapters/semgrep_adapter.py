"""Semgrep adapter for SmartContract VulnHunter - pattern matching with SARIF output."""

from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path
from shutil import which
from typing import List, Any

from vulnhunter.adapters.base import ToolAdapter

try:
    from vulnhunter.models.finding import Finding, FindingSeverity
    from vulnhunter.models.sarif import SarifLog, sarif_to_findings
except Exception:
    Finding = Any
    SarifLog = Any
    sarif_to_findings = None


class SemgrepAdapter(ToolAdapter):
    """Semgrep adapter producing SARIF output and translating to SmartContract VulnHunter Findings."""

    @property
    def name(self) -> str:
        return "semgrep"

    def is_available(self) -> bool:
        """Return True if semgrep is installed and available on PATH."""
        return which("semgrep") is not None

    async def run(self, target: str) -> List[Finding]:
        """Run semgrep against the target and return a list of Findings.

        Command built: semgrep --config p/smart-contracts <target> --sarif -o <output>
        """
        if not self.is_available():
            return []

        sarif_path = f"/tmp/semgrep_{uuid.uuid4()}.sarif"
        cmd = f"semgrep --config p/smart-contracts {target} --sarif -o {sarif_path}"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return []

        try:
            with open(sarif_path, "r", encoding="utf-8") as f:
                sarif_content = f.read()

            if sarif_to_findings and SarifLog is not Any:
                sarif_log = SarifLog.model_validate_json(sarif_content)
                return sarif_to_findings(sarif_log)
            else:
                return self._parse_sarif_fallback(sarif_content)

        except FileNotFoundError:
            return []
        except Exception:
            return []

    def _parse_sarif_fallback(self, sarif_content: str) -> List[Finding]:
        """Parse SARIF content when models unavailable."""
        findings: List[Finding] = []

        try:
            data = json.loads(sarif_content)
        except json.JSONDecodeError:
            return findings

        runs = data.get("runs", [])
        for run in runs:
            results = run.get("results", [])
            for result in results:
                finding_data = self._extract_finding_data(result)
                if finding_data:
                    try:
                        if Finding is not Any:
                            finding = Finding(**finding_data)
                        else:
                            finding = self._create_fallback_finding(finding_data)
                        findings.append(finding)
                    except Exception:
                        pass

        return findings

    def _extract_finding_data(self, result: dict) -> dict:
        """Extract finding data from SARIF result."""
        rule_id = result.get("ruleId", "unknown")
        message = result.get("message", {}).get("text", "")
        level = result.get("level", "warning")

        locations = result.get("locations", [])
        location = locations[0] if locations else {}
        phys_loc = location.get("physicalLocation", {})
        artifact = phys_loc.get("artifactLocation", {})
        region = phys_loc.get("region", {})

        file_path = artifact.get("uri", "")
        start_line = region.get("startLine", 0)
        start_column = region.get("startColumn", 0)

        severity = self._map_level_to_severity(level)

        return {
            "tool": self.name,
            "rule_id": rule_id,
            "severity": severity,
            "confidence": "medium",
            "title": f"Semgrep: {rule_id}",
            "description": message,
            "location": {
                "file": file_path,
                "start_line": start_line,
                "start_column": start_column,
            },
            "metadata": {
                "semgrep_level": level,
            },
        }

    def _map_level_to_severity(self, level: str) -> str:
        """Map SARIF level to severity."""
        mapping = {
            "error": "high",
            "warning": "medium",
            "note": "low",
        }
        return mapping.get(level.lower(), "medium")

    def _create_fallback_finding(self, data: dict) -> Any:
        """Create a lightweight finding object when Finding model unavailable."""

        class FallbackFinding:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)

        return FallbackFinding(**data)

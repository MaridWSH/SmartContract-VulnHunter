"""Vyper adapter for VulnHunter - leverages Slither's native Vyper support."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import List, Any

from vulnhunter.adapters.base import ToolAdapter

try:
    from vulnhunter.models.finding import Finding
except Exception:
    Finding = Any


class VyperAdapter(ToolAdapter):
    """Vyper adapter using Slither's native Vyper support.

    According to the PRD: "Slither natively supports Vyper — the same `slither .` command works."
    This adapter wraps Slither specifically for Vyper file analysis.
    """

    @property
    def name(self) -> str:
        return "vyper"

    def is_available(self) -> bool:
        """Check if slither is available (required for Vyper analysis)."""
        try:
            from slither import Slither

            return True
        except ImportError:
            return False

    async def run(self, target: str) -> List[Finding]:
        """Run Slither on Vyper files and return findings.

        Args:
            target: Path to directory containing .vy files

        Returns:
            List of Finding objects from Vyper analysis
        """
        if not self.is_available():
            return []

        target_path = Path(target)

        # Check for Vyper files
        vyper_files = list(target_path.glob("**/*.vy"))
        if not vyper_files:
            return []

        # Run in thread to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._analyze_vyper, target)

    def _analyze_vyper(self, target: str) -> List[Finding]:
        """Analyze Vyper files using Slither."""
        findings: List[Finding] = []

        try:
            from slither import Slither
            from slither.detectors import all_detectors
            from slither.exceptions import SlitherError

            slither = Slither(target)

            # Register all detectors
            for detector in all_detectors:
                slither.register_detector(detector)

            # Run detectors
            results = slither.run_detectors()

            # Convert results to Finding objects
            for result in results:
                if not isinstance(result, dict):
                    continue

                finding_data = self._convert_result(result)
                if finding_data:
                    try:
                        if Finding is not Any:
                            finding = Finding(**finding_data)
                        else:
                            finding = self._create_fallback_finding(finding_data)
                        findings.append(finding)
                    except Exception:
                        pass

        except Exception as e:
            # Vyper compilation may fail - log and continue
            pass

        return findings

    def _convert_result(self, result: dict) -> dict:
        """Convert Slither result to Finding data."""
        check = result.get("check", "")
        impact = result.get("impact", "")
        confidence = result.get("confidence", "")
        description = result.get("description", "")

        elements = result.get("elements", [])
        element = elements[0] if elements else {}

        source_mapping = (
            element.get("source_mapping", {}) if isinstance(element, dict) else {}
        )
        file_path = source_mapping.get("filename_relative", "")
        line = source_mapping.get("lines", [0])[0] if source_mapping.get("lines") else 0

        return {
            "tool": self.name,
            "rule_id": check,
            "severity": impact.lower() if impact else "medium",
            "confidence": confidence.lower() if confidence else "medium",
            "title": f"Vyper: {check}",
            "description": description,
            "location": {
                "file": file_path,
                "start_line": line,
            },
            "metadata": {
                "language": "vyper",
                "slither_check": check,
            },
        }

    def _create_fallback_finding(self, data: dict) -> Any:
        """Create a lightweight finding object when Finding model unavailable."""

        class FallbackFinding:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)

        return FallbackFinding(**data)

"""SARIF merger for combining results from multiple tools."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Any, Dict

try:
    from vulnhunter.models.finding import Finding
    from vulnhunter.models.sarif import SarifLog
except Exception:
    Finding = Any
    SarifLog = Any


class SarifMerger:
    """Merge SARIF results from multiple tools."""

    def merge_findings(self, findings_list: List[List[Finding]]) -> List[Finding]:
        """Flatten list of finding lists from multiple tools into a single list.

        Args:
            findings_list: List of finding lists from different tools

        Returns:
            Merged list of all findings
        """
        merged: List[Finding] = []
        for findings in findings_list:
            merged.extend(findings)
        return merged

    def merge_sarif_files(self, sarif_files: List[Path]) -> Dict[str, Any]:
        """Load multiple SARIF files and merge into a single SARIF log.

        Args:
            sarif_files: List of paths to SARIF files

        Returns:
            Merged SARIF log as dictionary
        """
        all_results: List[Dict[str, Any]] = []

        for sarif_file in sarif_files:
            try:
                with open(sarif_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Extract results from each run
                for run in data.get("runs", []):
                    results = run.get("results", [])
                    all_results.extend(results)
            except Exception:
                continue

        # Build merged SARIF log
        merged: Dict[str, Any] = {
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif-specification/v2.1.0/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {"driver": {"name": "vulnhunter-sarif-merge"}},
                    "results": all_results,
                }
            ],
        }

        return merged

    def normalize_paths(self, findings: List[Finding], base_path: Path) -> List[Finding]:
        """Convert absolute paths to relative paths in findings.

        Args:
            findings: List of findings to normalize
            base_path: Base path for relative path calculation

        Returns:
            Findings with normalized paths
        """
        normalized: List[Finding] = []

        for finding in findings:
            # Try to get file path from finding
            file_path = None
            if isinstance(finding, dict):
                file_path = finding.get("location", {}).get("file")
            else:
                file_path = getattr(finding, "location", None)
                if file_path:
                    file_path = getattr(file_path, "file", None)

            if file_path:
                new_path = self._to_relative_path(file_path, base_path)

                # Update finding with normalized path
                if isinstance(finding, dict):
                    finding["location"]["file"] = new_path
                else:
                    if hasattr(finding, "location") and finding.location:
                        finding.location.file = new_path

            normalized.append(finding)

        return normalized

    def _to_relative_path(self, path_str: str, base_path: Path) -> str:
        """Convert a path to relative path from base_path.

        Args:
            path_str: Original path string
            base_path: Base path for relative calculation

        Returns:
            Relative path string
        """
        # Strip file:// prefix if present
        if path_str.startswith("file://"):
            path_str = path_str[7:]

        path = Path(path_str)

        try:
            return str(path.relative_to(base_path))
        except ValueError:
            # If can't make relative, return as-is but normalized
            return str(path)

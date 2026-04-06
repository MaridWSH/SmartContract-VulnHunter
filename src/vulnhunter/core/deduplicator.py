"""Deduplicator for removing duplicate findings across tools."""

from __future__ import annotations

import hashlib
from typing import List, Set, Any
from pathlib import Path


try:
    from vulnhunter.models.finding import Finding
except Exception:
    Finding = Any


class Deduplicator:
    """Deduplicate findings based on fingerprints."""

    def __init__(self):
        self.seen_fingerprints: Set[str] = set()

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicates based on fingerprint.

        When duplicates are found, merges detecting tools and preserves highest severity.

        Args:
            findings: List of findings to deduplicate

        Returns:
            List of unique findings
        """
        deduped: List[Finding] = []

        for finding in findings:
            try:
                fingerprint = self.compute_fingerprint(finding)
            except Exception:
                # If can't fingerprint, keep the finding
                deduped.append(finding)
                continue

            if fingerprint not in self.seen_fingerprints:
                self.seen_fingerprints.add(fingerprint)
                deduped.append(finding)
            else:
                # Find existing finding with same fingerprint and merge
                self._merge_with_existing(deduped, finding, fingerprint)

        return deduped

    def compute_fingerprint(self, finding: Finding) -> str:
        """Compute a stable fingerprint for a finding.

        Uses rule_id + file_path + start_line for uniqueness.

        Args:
            finding: Finding to fingerprint

        Returns:
            Fingerprint string
        """
        # Extract fields from finding
        if isinstance(finding, dict):
            rule_id = finding.get("rule_id", "")
            location = finding.get("location", {})
            file_path = location.get("file", "") if isinstance(location, dict) else ""
            start_line = location.get("start_line", 0) if isinstance(location, dict) else 0
            description = finding.get("description", "")
        else:
            rule_id = getattr(finding, "rule_id", "")
            location = getattr(finding, "location", None)
            file_path = getattr(location, "file", "") if location else ""
            start_line = getattr(location, "start_line", 0) if location else 0
            description = getattr(finding, "description", "")

        # Normalize path
        file_path = self.normalize_path(str(file_path))

        # Create hash
        key = f"{rule_id}:{file_path}:{start_line}:{hash(description)}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def normalize_path(self, path: str) -> str:
        """Normalize a file path.

        Args:
            path: Path string to normalize

        Returns:
            Normalized path
        """
        # Remove file:// prefix
        if path.startswith("file://"):
            path = path[7:]

        # Normalize separators
        path = path.replace("\\", "/")

        return path

    def _merge_with_existing(
        self, deduped: List[Finding], new_finding: Finding, fingerprint: str
    ) -> None:
        """Merge a new finding with an existing duplicate.

        Preserves highest severity and merges detecting tools.

        Args:
            deduped: List of already deduplicated findings
            new_finding: New finding to merge
            fingerprint: Fingerprint of the finding
        """
        for existing in deduped:
            try:
                existing_fp = self.compute_fingerprint(existing)
            except Exception:
                continue

            if existing_fp == fingerprint:
                # Merge tools
                self._merge_tools(existing, new_finding)

                # Preserve highest severity
                self._preserve_highest_severity(existing, new_finding)
                break

    def _merge_tools(self, existing: Finding, new: Finding) -> None:
        """Merge detecting tools from two findings."""
        # Get tools from both findings
        existing_tool = self._get_tool(existing)
        new_tool = self._get_tool(new)

        # Create or update tools list
        tools = set()
        if existing_tool:
            tools.add(existing_tool)
        if new_tool:
            tools.add(new_tool)

        # Update existing finding
        if isinstance(existing, dict):
            existing["detecting_tools"] = sorted(tools)
        else:
            setattr(existing, "detecting_tools", sorted(tools))

    def _get_tool(self, finding: Finding) -> str:
        """Get tool name from finding."""
        if isinstance(finding, dict):
            return finding.get("tool", "")
        return getattr(finding, "tool", "")

    def _preserve_highest_severity(self, existing: Finding, new: Finding) -> None:
        """Preserve the highest severity between two findings."""
        severity_order = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }

        existing_sev = self._get_severity(existing)
        new_sev = self._get_severity(new)

        existing_rank = severity_order.get(existing_sev.lower(), 0)
        new_rank = severity_order.get(new_sev.lower(), 0)

        if new_rank > existing_rank:
            # Update to higher severity
            if isinstance(existing, dict):
                existing["severity"] = new_sev
            else:
                setattr(existing, "severity", new_sev)

    def _get_severity(self, finding: Finding) -> str:
        """Get severity from finding."""
        if isinstance(finding, dict):
            return finding.get("severity", "low")
        return getattr(finding, "severity", "low")

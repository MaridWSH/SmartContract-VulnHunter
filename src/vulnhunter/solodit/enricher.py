"""Solodit Knowledge Base integration for SmartContract VulnHunter.

This module provides enrichment capabilities for scan findings
using the Solodit vulnerability database with 62K+ real-world findings.
"""

from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

# Add solodit_kb to path
sys.path.insert(0, "/home/ubuntu/solodit_kb")

try:
    from opencode_adapter import SoloditKB
    SOLODIT_AVAILABLE = True
except ImportError:
    SOLODIT_AVAILABLE = False


@dataclass
class EnrichedFinding:
    """A finding enriched with Solodit KB data."""

    original_finding: Any
    similar_vulnerabilities: List[Dict] = field(default_factory=list)
    historical_exploits: List[Dict] = field(default_factory=list)
    severity_confidence: float = 0.0
    exploitability_score: float = 0.0


class SoloditEnricher:
    """Enrich SmartContract VulnHunter findings with Solodit KB data."""

    def __init__(self):
        if not SOLODIT_AVAILABLE:
            raise ImportError("Solodit KB not available. Check /home/ubuntu/solodit_kb/")
        self.kb = SoloditKB()

    async def enrich_findings(self, findings: List) -> List[EnrichedFinding]:
        """Enrich a list of findings with Solodit data."""
        enriched = []
        for finding in findings:
            enriched_finding = await self.enrich_single(finding)
            enriched.append(enriched_finding)
        return enriched

    async def enrich_single(self, finding) -> EnrichedFinding:
        """Enrich a single finding with Solodit data."""
        # Extract search terms from finding
        search_query = self._build_search_query(finding)

        # Search for similar vulnerabilities
        similar = self.kb.search(
            query=search_query, limit=5, severity=getattr(finding, "severity", None)
        )

        # Find historical exploits (high severity only)
        historical = []
        if getattr(finding, "severity", "") in ["CRITICAL", "HIGH"]:
            historical = self.kb.search(
                query=search_query + " exploit attack", limit=3, severity="HIGH"
            )

        # Calculate scores
        severity_confidence = self._calculate_severity_confidence(finding, similar)
        exploitability = self._calculate_exploitability(finding, similar)

        return EnrichedFinding(
            original_finding=finding,
            similar_vulnerabilities=similar,
            historical_exploits=historical,
            severity_confidence=severity_confidence,
            exploitability_score=exploitability,
        )

    def _build_search_query(self, finding) -> str:
        """Build a search query from a finding."""
        parts = []

        # Add check/vulnerability type if available
        check = getattr(finding, "check", None)
        if check:
            parts.append(check)

        # Add description
        description = getattr(finding, "description", "")
        if description:
            # Truncate long descriptions
            parts.append(description[:200])

        # Add function name if available
        function = getattr(finding, "function", None)
        if function:
            parts.append(function)

        return " ".join(parts) if parts else "smart contract vulnerability"

    def _calculate_severity_confidence(self, finding, similar: List[Dict]) -> float:
        """Calculate confidence in severity based on similar findings."""
        if not similar:
            return 0.5

        finding_sev = getattr(finding, "severity", "MEDIUM")
        matches = 0

        for vuln in similar:
            vuln_sev = vuln.get("severity", "MEDIUM")
            if vuln_sev == finding_sev:
                matches += 1

        return matches / len(similar) if similar else 0.5

    def _calculate_exploitability(self, finding, similar: List[Dict]) -> float:
        """Calculate exploitability score based on similar findings."""
        if not similar:
            return 0.5

        # Count how many similar findings had real exploits
        exploit_count = 0
        for vuln in similar:
            # Check if finding mentions exploit/attack
            desc = vuln.get("description", "").lower()
            if any(word in desc for word in ["exploit", "attack", "stolen", "drain"]):
                exploit_count += 1

        return exploit_count / len(similar) if similar else 0.5

    def get_exploit_references(self, finding) -> List[Dict]:
        """Get real-world exploit references for a finding type."""
        query = self._build_search_query(finding)

        # Search for high severity examples with exploits
        results = self.kb.search(query=query, limit=3, severity="HIGH")

        # Extract references
        references = []
        for result in results:
            ref = {
                "finding_id": result.get("finding_id"),
                "protocol": result.get("protocol"),
                "severity": result.get("severity"),
                "description": result.get("description", "")[:300],
            }
            references.append(ref)

        return references

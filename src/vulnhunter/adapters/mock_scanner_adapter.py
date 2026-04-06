"""Mock scanner adapter for testing orchestration without external tools."""

from __future__ import annotations

from typing import List, Any
from pathlib import Path

from vulnhunter.adapters.base import ToolAdapter

try:
    from vulnhunter.models.finding import Finding, FindingSeverity
except Exception:
    Finding = Any


class MockScannerAdapter(ToolAdapter):
    """Mock scanner for testing framework without external dependencies."""

    @property
    def name(self) -> str:
        return "mock-scanner"

    def is_available(self) -> bool:
        """Always available for testing."""
        return True

    async def run(self, target: str) -> List[Finding]:
        """Return mock findings for testing."""
        # Detect target type based on files present
        target_path = Path(target)

        findings = []

        # Check for Solidity files
        if list(target_path.glob("**/*.sol")):
            findings.append(
                self._create_finding(
                    rule_id="SOLIDITY-001",
                    title="Mock Solidity Issue",
                    severity="high",
                    description="Mock finding for Solidity code",
                    file="contracts/Example.sol",
                    line=42,
                )
            )

        # Check for Rust files
        if list(target_path.glob("**/*.rs")):
            findings.append(
                self._create_finding(
                    rule_id="RUST-001",
                    title="Mock Rust Issue",
                    severity="medium",
                    description="Mock finding for Rust code",
                    file="src/lib.rs",
                    line=10,
                )
            )

        # Check for Vyper files
        if list(target_path.glob("**/*.vy")):
            findings.append(
                self._create_finding(
                    rule_id="VYPER-001",
                    title="Mock Vyper Issue",
                    severity="low",
                    description="Mock finding for Vyper code",
                    file="contracts/Example.vy",
                    line=15,
                )
            )

        # Check for Cairo files
        if list(target_path.glob("**/*.cairo")):
            findings.append(
                self._create_finding(
                    rule_id="CAIRO-001",
                    title="Mock Cairo Issue",
                    severity="medium",
                    description="Mock finding for Cairo code",
                    file="src/example.cairo",
                    line=20,
                )
            )

        return findings

    def _create_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        description: str,
        file: str,
        line: int,
    ) -> Finding:
        """Create a mock finding."""
        finding_data = {
            "tool": self.name,
            "rule_id": rule_id,
            "severity": severity,
            "confidence": "high",
            "title": title,
            "description": description,
            "location": {
                "file": file,
                "start_line": line,
            },
            "metadata": {
                "mock": True,
            },
        }

        try:
            if Finding is not Any:
                return Finding(**finding_data)
            else:
                return self._create_fallback_finding(finding_data)
        except Exception:
            return self._create_fallback_finding(finding_data)

    def _create_fallback_finding(self, data: dict) -> Any:
        """Create a lightweight finding object when Finding model unavailable."""

        class FallbackFinding:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)

            def dict(self):
                return self.__dict__

        return FallbackFinding(**data)

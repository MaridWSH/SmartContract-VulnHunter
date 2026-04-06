"""Reconnaissance report models for SmartContract VulnHunter."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ContractInfo(BaseModel):
    """Information about a key contract."""

    name: str
    address: Optional[str] = None
    path: str
    lines_of_code: int
    functions: int
    external_functions: int
    is_proxy: bool = False
    is_implementation: bool = False
    is_admin_contract: bool = False


class FileChangeInfo(BaseModel):
    """Information about a recently changed file."""

    file_path: str
    commit_hash: str
    commit_message: str
    author: str
    date: datetime
    lines_changed: int


class TodoItem(BaseModel):
    """Developer TODO item found in code."""

    file_path: str
    line_number: int
    todo_text: str
    priority: Optional[str] = None


class AuditInfo(BaseModel):
    """Information about a prior audit."""

    auditor: str
    date: str
    report_url: Optional[str] = None
    scope: List[str] = Field(default_factory=list)
    findings_count: Optional[int] = None


class HotZone(BaseModel):
    """Priority target for deep analysis."""

    file_path: str
    function_name: Optional[str] = None
    reason: str
    risk_score: int = Field(ge=1, le=10)
    attack_vectors: List[str] = Field(default_factory=list)


class ReconReport(BaseModel):
    """Structured reconnaissance report.

    This is the foundation document that feeds into Kimi's context
    for intelligent scan orchestration and vulnerability hunting.
    """

    # Metadata
    version: str = "1.0.0"
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    # Target
    repo_url: str
    target_path: str = ""  # Local path for scanning
    repo_name: str
    commit_hash: str
    commit_message: str
    audit_date: datetime = Field(default_factory=datetime.utcnow)
    ecosystems: List[str] = Field(default_factory=list)

    # Build
    build_status: str = "UNKNOWN"  # "PASS" | "FAIL" | "PARTIAL" | "UNKNOWN"
    build_errors: List[str] = Field(default_factory=list)
    compiler_versions: Dict[str, str] = Field(default_factory=dict)
    framework: Optional[str] = None  # foundry, hardhat, anchor, scarb

    # Scope
    in_scope_files: List[str] = Field(default_factory=list)
    out_of_scope_files: List[str] = Field(default_factory=list)
    total_loc: int = 0
    total_functions: int = 0
    external_functions: int = 0

    # Protocol
    protocol_type: Optional[str] = None  # lending, dex, vault, bridge, etc.
    protocol_description: Optional[str] = None
    tvl_usd: Optional[float] = None
    chains: List[str] = Field(default_factory=list)
    upgrade_pattern: Optional[str] = None  # proxy, diamond, none

    # Architecture
    key_contracts: List[ContractInfo] = Field(default_factory=list)
    trust_hierarchy: Dict[str, List[str]] = Field(default_factory=dict)
    external_dependencies: List[str] = Field(default_factory=list)
    token_flows: List[str] = Field(default_factory=list)

    # Attack Surface
    external_call_sites: int = 0
    payable_functions: int = 0
    oracle_dependencies: int = 0
    assembly_blocks: int = 0
    unchecked_blocks: int = 0
    signature_operations: int = 0
    cross_contract_interactions: int = 0
    delegatecall_sites: int = 0
    selfdestruct_sites: int = 0

    # Risk Indicators
    test_coverage_percent: Optional[float] = None
    untested_functions: List[str] = Field(default_factory=list)
    recently_changed_files: List[FileChangeInfo] = Field(default_factory=list)
    developer_todos: List[TodoItem] = Field(default_factory=list)
    single_author_files: List[str] = Field(default_factory=list)
    custom_implementations: List[str] = Field(default_factory=list)

    # Dependencies
    dependency_versions: Dict[str, str] = Field(default_factory=dict)
    known_vulnerable_deps: List[str] = Field(default_factory=list)
    cargo_audit_results: Optional[List[str]] = None
    npm_audit_results: Optional[List[str]] = None

    # Prior Security
    previous_audits: List[AuditInfo] = Field(default_factory=list)
    known_issues: List[str] = Field(default_factory=list)
    security_commits: List[FileChangeInfo] = Field(default_factory=list)
    bug_bounty_url: Optional[str] = None

    # Hot Zones (priority targets)
    hot_zones: List[HotZone] = Field(default_factory=list)

    # Raw data for LLM analysis
    raw_grep_results: Dict[str, Any] = Field(default_factory=dict)

    def to_markdown(self) -> str:
        """Generate a human-readable markdown report."""
        lines = [
            f"# Reconnaissance Report: {self.repo_name}",
            f"",
            f"**Commit:** `{self.commit_hash[:8]}` — {self.commit_message[:60]}{'...' if len(self.commit_message) > 60 else ''}",
            f"**Date:** {self.generated_at.isoformat()}",
            f"**Ecosystems:** {', '.join(self.ecosystems)}",
            f"**Build Status:** {'✅ PASS' if self.build_status == 'PASS' else '❌ FAIL' if self.build_status == 'FAIL' else '⚠️ PARTIAL'}",
            f"",
            f"## Protocol Overview",
            f"",
        ]

        if self.protocol_type:
            lines.extend(
                [
                    f"**Type:** {self.protocol_type}",
                    f"",
                ]
            )
        if self.protocol_description:
            lines.extend(
                [
                    f"**Description:** {self.protocol_description}",
                    f"",
                ]
            )
        if self.tvl_usd:
            lines.append(f"**TVL:** ${self.tvl_usd:,.2f}")
        if self.chains:
            lines.append(f"**Chains:** {', '.join(self.chains)}")
        lines.append("")

        # Codebase stats
        lines.extend(
            [
                f"## Codebase Statistics",
                f"",
                f"- **Total LOC:** {self.total_loc:,}",
                f"- **Total Functions:** {self.total_functions}",
                f"- **External Functions:** {self.external_functions}",
                f"- **Test Coverage:** {self.test_coverage_percent:.1f}%"
                if self.test_coverage_percent
                else "- **Test Coverage:** Unknown",
                f"- **In-Scope Files:** {len(self.in_scope_files)}",
                f"",
            ]
        )

        # Attack Surface
        lines.extend(
            [
                f"## Attack Surface",
                f"",
                f"- **External Call Sites:** {self.external_call_sites}",
                f"- **Payable Functions:** {self.payable_functions}",
                f"- **Oracle Dependencies:** {self.oracle_dependencies}",
                f"- **Signature Operations:** {self.signature_operations}",
                f"- **Assembly Blocks:** {self.assembly_blocks}",
                f"- **Delegatecall Sites:** {self.delegatecall_sites}",
                f"",
            ]
        )

        # Hot Zones
        if self.hot_zones:
            lines.extend(
                [
                    f"## 🔥 Hot Zones (Priority Targets)",
                    f"",
                ]
            )
            for zone in self.hot_zones[:10]:  # Top 10
                lines.extend(
                    [
                        f"### {zone.file_path}",
                        f"- **Risk Score:** {zone.risk_score}/10",
                        f"- **Reason:** {zone.reason}",
                    ]
                )
                if zone.attack_vectors:
                    lines.append(f"- **Attack Vectors:** {', '.join(zone.attack_vectors)}")
                lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export as dictionary."""
        return self.model_dump()

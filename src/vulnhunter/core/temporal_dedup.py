"""Temporal Deduplicator - Git-aware deduplication.

Prevents submitting findings that have already been fixed in the codebase
by tracking findings across commits.
"""

from __future__ import annotations

import json
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, asdict


@dataclass
class TemporalFingerprint:
    """A git-aware fingerprint that tracks a finding across time."""

    base_fingerprint: str
    commit_hash: str
    commit_date: str
    file_path: str
    line_number: int
    rule_id: str
    first_seen_commit: Optional[str] = None
    first_seen_date: Optional[str] = None
    fixed_in_commit: Optional[str] = None
    fixed_in_date: Optional[str] = None
    status: str = "open"  # open, fixed, stale

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TemporalFingerprint":
        return cls(**data)


class TemporalDeduplicator:
    """Git-aware deduplicator that prevents submitting fixed bugs.

    Tracks findings across commits to identify:
    - New findings (not seen before)
    - Fixed findings (previously reported, now resolved)
    - Stale findings (code changed but issue may persist)
    """

    def __init__(self, state_file: Optional[Path] = None):
        if state_file is None:
            state_file = Path.cwd() / ".vulnhunter" / "temporal-state.json"
        self.state_file = state_file
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        self.findings_db: Dict[str, TemporalFingerprint] = {}
        self._load_state()

    def _load_state(self) -> None:
        """Load previous findings state."""
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text())
                for fp, tf_data in data.get("findings", {}).items():
                    self.findings_db[fp] = TemporalFingerprint.from_dict(tf_data)
            except (json.JSONDecodeError, KeyError):
                pass

    def save_state(self) -> None:
        """Save current findings state."""
        data = {
            "last_updated": datetime.utcnow().isoformat(),
            "findings": {fp: tf.to_dict() for fp, tf in self.findings_db.items()},
        }
        self.state_file.write_text(json.dumps(data, indent=2))

    def deduplicate(
        self,
        findings: List[Any],
        target_path: Path,
    ) -> "DeduplicationResult":
        """Deduplicate findings with temporal awareness.

        Args:
            findings: List of findings to deduplicate
            target_path: Path to the target codebase

        Returns:
            DeduplicationResult with new, fixed, and stale findings
        """
        current_commit = self._get_current_commit(target_path)
        current_date = self._get_commit_date(target_path, current_commit)

        new_findings = []
        fixed_findings = []
        stale_findings = []
        duplicate_findings = []

        for finding in findings:
            tf = self._create_temporal_fingerprint(
                finding, target_path, current_commit, current_date
            )

            if tf.base_fingerprint in self.findings_db:
                existing = self.findings_db[tf.base_fingerprint]

                if existing.status == "fixed":
                    # This was fixed before - it's a regression!
                    new_findings.append(finding)
                    existing.status = "regression"
                    existing.first_seen_commit = existing.first_seen_commit or existing.commit_hash
                    existing.first_seen_date = existing.first_seen_date or existing.commit_date
                elif self._is_same_location(existing, tf):
                    # Same location, same issue - duplicate
                    duplicate_findings.append(finding)
                else:
                    # Code moved - mark as stale, treat as new
                    existing.status = "stale"
                    stale_findings.append(finding)
                    self.findings_db[tf.base_fingerprint] = tf
            else:
                # New finding
                new_findings.append(finding)
                self.findings_db[tf.base_fingerprint] = tf

        # Check for fixed findings (in DB but not in current findings)
        current_fps = {self._compute_base_fp(f) for f in findings}
        for fp, tf in self.findings_db.items():
            if fp not in current_fps and tf.status == "open":
                tf.status = "fixed"
                tf.fixed_in_commit = current_commit
                tf.fixed_in_date = current_date
                fixed_findings.append(tf)

        return DeduplicationResult(
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            stale_findings=stale_findings,
            duplicate_findings=duplicate_findings,
            current_commit=current_commit,
        )

    def _create_temporal_fingerprint(
        self,
        finding: Any,
        target_path: Path,
        commit_hash: str,
        commit_date: str,
    ) -> TemporalFingerprint:
        """Create a temporal fingerprint for a finding."""
        base_fp = self._compute_base_fp(finding)

        # Extract location info
        if isinstance(finding, dict):
            location = finding.get("location", {})
            file_path = location.get("file", "") if isinstance(location, dict) else ""
            line_number = location.get("start_line", 0) if isinstance(location, dict) else 0
            rule_id = finding.get("rule_id", "")
        else:
            location = getattr(finding, "location", None)
            file_path = getattr(location, "file", "") if location else ""
            line_number = getattr(location, "start_line", 0) if location else 0
            rule_id = getattr(finding, "rule_id", "")

        # Normalize path relative to target
        try:
            file_path = str(Path(file_path).relative_to(target_path))
        except ValueError:
            pass

        return TemporalFingerprint(
            base_fingerprint=base_fp,
            commit_hash=commit_hash,
            commit_date=commit_date,
            file_path=file_path,
            line_number=line_number,
            rule_id=rule_id,
        )

    def _compute_base_fp(self, finding: Any) -> str:
        """Compute base fingerprint for a finding."""
        if isinstance(finding, dict):
            rule_id = finding.get("rule_id", "")
            location = finding.get("location", {})
            file_path = location.get("file", "") if isinstance(location, dict) else ""
            start_line = location.get("start_line", 0) if isinstance(location, dict) else 0
            code_snippet = finding.get("code_snippet", "")[:100]
        else:
            rule_id = getattr(finding, "rule_id", "")
            location = getattr(finding, "location", None)
            file_path = getattr(location, "file", "") if location else ""
            start_line = getattr(location, "start_line", 0) if location else 0
            code_snippet = getattr(finding, "code_snippet", "")[:100]

        # Normalize path
        file_path = str(file_path).replace("\\", "/")

        # Create hash
        key = f"{rule_id}:{file_path}:{start_line}:{hash(code_snippet)}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def _is_same_location(self, a: TemporalFingerprint, b: TemporalFingerprint) -> bool:
        """Check if two fingerprints refer to the same code location."""
        return a.file_path == b.file_path and abs(a.line_number - b.line_number) <= 3

    def _get_current_commit(self, target_path: Path) -> str:
        """Get current git commit hash."""
        try:
            result = subprocess.run(
                ["git", "-C", str(target_path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return "unknown"

    def _get_commit_date(self, target_path: Path, commit_hash: str) -> str:
        """Get commit date."""
        try:
            result = subprocess.run(
                ["git", "-C", str(target_path), "show", "-s", "--format=%ci", commit_hash],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            return datetime.utcnow().isoformat()

    def get_stats(self) -> Dict[str, int]:
        """Get deduplication statistics."""
        stats = {"open": 0, "fixed": 0, "stale": 0, "regression": 0}
        for tf in self.findings_db.values():
            stats[tf.status] = stats.get(tf.status, 0) + 1
        return stats


@dataclass
class DeduplicationResult:
    """Result of temporal deduplication."""

    new_findings: List[Any]
    fixed_findings: List[TemporalFingerprint]
    stale_findings: List[Any]
    duplicate_findings: List[Any]
    current_commit: str

    @property
    def total_input(self) -> int:
        return (
            len(self.new_findings)
            + len(self.fixed_findings)
            + len(self.stale_findings)
            + len(self.duplicate_findings)
        )

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def fixed_count(self) -> int:
        return len(self.fixed_findings)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicate_findings)

    def to_report(self) -> str:
        """Generate a human-readable report."""
        lines = [
            "# Temporal Deduplication Report",
            f"",
            f"Current Commit: `{self.current_commit[:8]}`",
            f"",
            f"## Summary",
            f"- **Total Findings Processed:** {self.total_input}",
            f"- **New Findings:** {self.new_count} ✅",
            f"- **Fixed Findings:** {self.fixed_count} 🎉",
            f"- **Duplicates:** {self.duplicate_count} (skipped)",
            f"- **Stale:** {len(self.stale_findings)} (code moved)",
        ]

        if self.fixed_findings:
            lines.extend(
                [
                    f"",
                    f"## Fixed Issues",
                ]
            )
            for tf in self.fixed_findings[:5]:
                lines.append(
                    f"- {tf.rule_id} in {tf.file_path} (fixed in {tf.fixed_in_commit[:8]})"
                )

        return "\n".join(lines)

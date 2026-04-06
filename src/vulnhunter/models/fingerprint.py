"""Fingerprint computation for finding deduplication."""

import hashlib
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .finding import Finding


class FingerprintGenerator:
    """Generates deterministic fingerprints for vulnerability findings.

    Fingerprints are used to identify duplicate findings across different
    tool runs, allowing for deduplication and tracking of issues over time.
    """

    @staticmethod
    def normalize_path(path: str) -> str:
        normalized = path.replace("\\", "/")
        while "//" in normalized:
            normalized = normalized.replace("//", "/")
        if re.match(r"^[a-zA-Z]:/", normalized):
            normalized = normalized[3:]
            if normalized.startswith("Users/"):
                normalized = re.sub(r"^Users/[^/]+/", "", normalized, count=1)
            elif normalized.startswith("home/"):
                normalized = re.sub(r"^home/[^/]+/", "", normalized, count=1)
        else:
            normalized = re.sub(r"^/home/[^/]+/", "", normalized, count=1)
            normalized = re.sub(r"^/Users/[^/]+/", "", normalized, count=1)
        normalized = re.sub(r"^/[^/]+/[^/]+/", "", normalized, count=1)
        normalized = re.sub(r"^\./", "", normalized)
        normalized = normalized.lstrip("/")
        return normalized

    @staticmethod
    def _normalize_description(description: str) -> str:
        """Normalize description for consistent hashing.

        Removes whitespace variations that shouldn't affect deduplication.

        Args:
            description: The finding description.

        Returns:
            Normalized description string.
        """
        # Normalize whitespace: collapse multiple spaces/newlines to single space
        normalized = " ".join(description.split())
        return normalized.lower().strip()

    @staticmethod
    def compute(finding: "Finding") -> str:
        """Compute a deterministic fingerprint for a finding.

        The fingerprint is based on:
        - rule_id: The detector/rule that found the issue
        - file_path: Normalized source file path
        - start_line: Line number where the issue was found
        - description_hash: Hash of the normalized description

        This combination provides good deduplication while being stable
        across different tool runs.

        Args:
            finding: The Finding object to fingerprint.

        Returns:
            A 16-character hexadecimal fingerprint string.
        """
        normalized_path = FingerprintGenerator.normalize_path(finding.location.file)
        normalized_desc = FingerprintGenerator._normalize_description(
            finding.description
        )

        # Compute hash of description for inclusion in key
        desc_hash = hashlib.sha256(normalized_desc.encode()).hexdigest()[:8]

        # Build the fingerprint key
        key = (
            f"{finding.rule_id}:"
            f"{normalized_path}:"
            f"{finding.location.start_line}:"
            f"{desc_hash}"
        )

        # Generate final fingerprint
        fingerprint = hashlib.sha256(key.encode()).hexdigest()[:16]

        return fingerprint

    @staticmethod
    def compute_raw(
        rule_id: str, file_path: str, start_line: int, description: str
    ) -> str:
        """Compute a fingerprint from raw components.

        Useful when you don't have a Finding object yet.

        Args:
            rule_id: The detector/rule identifier.
            file_path: Path to the source file.
            start_line: Line number where the issue was found.
            description: Description of the finding.

        Returns:
            A 16-character hexadecimal fingerprint string.
        """
        from .finding import Finding, FindingConfidence, FindingSeverity, SourceLocation

        # Create a minimal Finding for computation
        finding = Finding(
            tool="",
            rule_id=rule_id,
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.MEDIUM,
            title="",
            description=description,
            location=SourceLocation(file=file_path, start_line=start_line),
        )

        return FingerprintGenerator.compute(finding)

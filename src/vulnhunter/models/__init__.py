"""Vulnhunter core models package.

Exposes the core data models for findings, SARIF representation and
fingerprints used for deduplication.
"""

from .finding import Finding, FindingSeverity, FindingConfidence, SourceLocation
from .severity_matrix import derive_severity
from .sarif import (
    findings_to_sarif,
    sarif_to_findings,
    SarifLog,
    SarifRun,
    SarifResult,
    SarifTool,
)
from .fingerprint import FingerprintGenerator
from . import severity_matrix  # expose module for consumers as severity_matrix

__all__ = [
    "Finding",
    "FindingSeverity",
    "FindingConfidence",
    "SourceLocation",
    "findings_to_sarif",
    "sarif_to_findings",
    "SarifLog",
    "SarifRun",
    "SarifResult",
    "SarifTool",
    "FingerprintGenerator",
    "derive_severity",
    "severity_matrix",
]

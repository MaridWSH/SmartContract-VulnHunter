from __future__ import annotations

import uuid
from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SourceLocation(BaseModel):
    file: str = Field(
        ..., description="Path to the source file containing the finding."
    )
    start_line: int = Field(..., description="Starting line number (1-based).")
    start_column: Optional[int] = Field(
        None, description="Starting column number (1-based)."
    )
    end_line: Optional[int] = Field(None, description="Ending line number (1-based).")
    end_column: Optional[int] = Field(
        None, description="Ending column number (1-based)."
    )


class Finding(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the finding.",
    )
    tool: str = Field(..., description="Which tool found it (e.g., slither, bandit).")
    rule_id: str = Field(
        ..., description="Detector/rule identifier that produced this finding."
    )
    severity: FindingSeverity = Field(..., description="Severity of the finding.")
    confidence: FindingConfidence = Field(
        ..., description="Confidence level of the finding."
    )
    title: str = Field(..., description="Short title for the finding.")
    description: str = Field(..., description="Detailed description of the finding.")
    location: SourceLocation = Field(
        ..., description="Location information for the finding."
    )
    code_snippet: Optional[str] = Field(
        None, description="Code snippet illustrating the issue."
    )
    recommendation: Optional[str] = Field(
        None, description="Recommended remediation or action."
    )
    references: List[str] = Field(
        default_factory=list, description="External references for the finding."
    )
    fingerprint: Optional[str] = Field(
        None, description="Deterministic fingerprint for deduplication."
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Arbitrary extra data about the finding."
    )

    def compute_fingerprint(self) -> str:
        from .fingerprint import FingerprintGenerator

        self.fingerprint = FingerprintGenerator.compute(self)
        return self.fingerprint

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "Finding":
        return cls.model_validate_json(data)

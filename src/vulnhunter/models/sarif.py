from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from .finding import Finding, FindingSeverity, FindingConfidence, SourceLocation


# SARIF level type aligns with SARIF 2.1.0 spec (note, warning, error, none)
SARIF_LEVELS = {"none", "note", "warning", "error"}


class SarifLog(BaseModel):
    version: str = Field(default="2.1.0", description="SARIF version.")
    runs: List["SarifRun"] = Field(
        default_factory=list, description="List of SARIF runs."
    )

    # JSON helpers
    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "SarifLog":
        return cls.model_validate_json(data)


class SarifRun(BaseModel):
    tool: "SarifTool" = Field(..., description="Tool metadata for this run.")
    results: List["SarifResult"] = Field(
        default_factory=list, description="Findings/results."
    )

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "SarifRun":
        return cls.model_validate_json(data)


class SarifTool(BaseModel):
    driver: "SarifDriver" = Field(
        ..., description="Driver metadata for this SARIF run."
    )

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "SarifTool":
        return cls.model_validate_json(data)


class SarifDriver(BaseModel):
    name: str = Field(..., description="Tool name (e.g., Slither, Bandit).")
    information_uri: Optional[str] = Field(
        None, description="URL with more information about the tool."
    )
    version: Optional[str] = Field(None, description="Tool version.")
    rules: Optional[List[Dict[str, Any]]] = Field(
        default=None, description="Optional rule metadata."
    )

    def to_json(self) -> str:
        return self.model_dump_json()


class Message(BaseModel):
    text: str = Field(..., description="Human-readable message for the result.")


class Region(BaseModel):
    startLine: int
    startColumn: Optional[int] = None
    endLine: Optional[int] = None
    endColumn: Optional[int] = None


class ArtifactLocation(BaseModel):
    uri: str


class PhysicalLocation(BaseModel):
    artifactLocation: ArtifactLocation
    region: Optional[Region] = None


class Location(BaseModel):
    physicalLocation: PhysicalLocation


class SarifResult(BaseModel):
    ruleId: str
    level: Optional[str] = Field(
        None, description="SARIF level: none|note|warning|error"
    )
    message: Message
    locations: List[Location] = Field(default_factory=list)
    fingerprints: Optional[Dict[str, str]] = Field(default=None)
    properties: Optional[Dict[str, Any]] = Field(default=None)

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, data: str) -> "SarifResult":
        return cls.model_validate_json(data)


# Utility conversion helpers
def findings_to_sarif(findings: List[Finding]) -> SarifLog:
    if not findings:
        return SarifLog(runs=[])

    from collections import defaultdict

    findings_by_tool: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        findings_by_tool[f.tool].append(f)

    runs: List[SarifRun] = []
    for tool_name, tool_findings in findings_by_tool.items():
        results: List[SarifResult] = []
        for f in tool_findings:
            level = _sev_to_sarif_level(f.severity)
            message_text = f"{f.title}: {f.description}"

            location = Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(
                        uri=_normalize_sarif_uri(f.location.file)
                    ),
                    region=Region(
                        startLine=f.location.start_line,
                        startColumn=f.location.start_column,
                        endLine=f.location.end_line,
                        endColumn=f.location.end_column,
                    ),
                )
            )

            result = SarifResult(
                ruleId=f.rule_id,
                level=level,
                message=Message(text=message_text),
                locations=[location],
                fingerprints={"fingerprint": f.fingerprint} if f.fingerprint else None,
                properties=f.metadata or None,
            )
            results.append(result)

        tool = SarifTool(
            driver=SarifDriver(
                name=tool_name, information_uri=None, version=None, rules=None
            )
        )
        run = SarifRun(tool=tool, results=results)
        runs.append(run)

    return SarifLog(runs=runs)


def sarif_to_findings(sarif: SarifLog) -> List[Finding]:
    findings: List[Finding] = []
    for run in sarif.runs:
        tool_name = (
            run.tool.driver.name
            if run.tool and run.tool.driver and run.tool.driver.name
            else "unknown"
        )
        for res in run.results:
            loc = res.locations[0].physicalLocation if res.locations else None
            file_path = loc.artifactLocation.uri if loc else ""
            start_line = loc.region.startLine if loc and loc.region else 1
            start_col = loc.region.startColumn if loc and loc.region else None
            end_line = loc.region.endLine if loc and loc.region else None
            end_col = loc.region.endColumn if loc and loc.region else None

            location = SourceLocation(
                file=file_path,
                start_line=start_line,
                start_column=start_col,
                end_line=end_line,
                end_column=end_col,
            )

            finding = Finding(
                tool=tool_name,
                rule_id=res.ruleId,
                severity=_sarif_level_to_severity(res.level),
                confidence=FindingConfidence.HIGH,
                title=res.message.text.split(":", 1)[0]
                if res.message and res.message.text
                else res.ruleId,
                description=res.message.text if res.message else "",
                location=location,
                fingerprint=res.fingerprints.get("fingerprint")
                if res.fingerprints
                else None,
                metadata=res.properties or {},
            )
            findings.append(finding)
    return findings


# Internal helpers
def _normalize_sarif_uri(uri: str) -> str:
    # Basic normalization: keep as-is but ensure POSIX style
    if not uri:
        return uri
    return uri.replace("\\", "/")


def _sev_to_sarif_level(sev: FindingSeverity) -> Optional[str]:
    if sev in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
        return "error"
    if sev == FindingSeverity.MEDIUM:
        return "warning"
    if sev in (FindingSeverity.LOW, FindingSeverity.INFO):
        return "note"
    return None


def _sarif_level_to_severity(level: Optional[str]) -> FindingSeverity:
    if level == "error":
        return FindingSeverity.CRITICAL
    if level == "warning":
        return FindingSeverity.MEDIUM
    if level == "note":
        return FindingSeverity.LOW
    return FindingSeverity.MEDIUM

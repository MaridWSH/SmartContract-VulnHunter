"""Slither adapter for Vulnhunter using Python API (no subprocess).

This adapter wires Slither's Python library into Vulnhunter, running all
built-in detectors and translating findings into Vulnhunter's Finding model.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from vulnhunter.adapters.base import ToolAdapter
from vulnhunter.models import (
    Finding,
    FindingSeverity,
    FindingConfidence,
    SourceLocation,
)

# Optional: Slither imports are guarded to allow import-time failure gracefully
_Slither = None  # type: ignore
_DetectorAll = None  # type: ignore
_AbstractDetector = None  # type: ignore
_SlitherException = None  # type: ignore
_SlitherError = None  # type: ignore

try:
    from slither import Slither
    from slither.detectors import all_detectors
    from slither.detectors.abstract_detector import AbstractDetector  # type: ignore

    # Common exception names in Slither
    from slither.exceptions import SlitherException, SlitherError  # type: ignore

    _Slither = Slither
    _DetectorAll = all_detectors
    _AbstractDetector = AbstractDetector
    _SlitherException = SlitherException
    _SlitherError = SlitherError
except Exception:  # pragma: no cover - optional dependency
    # Keep placeholders for typing/flow; actual import handled in runtime path
    _Slither = None  # type: ignore
    _DetectorAll = None  # type: ignore
    _AbstractDetector = None  # type: ignore
    _SlitherException = None  # type: ignore
    _SlitherError = None  # type: ignore

logger = logging.getLogger(__name__)


class SlitherAdapter(ToolAdapter):
    name = "slither"

    def is_available(self) -> bool:
        """Return True if Slither Python package is importable."""
        try:
            # Import guard already performed at module load; just ensure symbol exists
            return _Slither is not None  # type: ignore
        except Exception:
            return False

    async def run(self, target: str) -> List[Finding]:  # type: ignore[override]
        findings: List[Finding] = []

        if _Slither is None:
            logger.warning("Slither Python library not available; skipping adapter run.")
            return findings

        try:
            slither = _Slither(target)  # type: ignore  # Slither constructor
        except Exception as exc:
            logger.warning(f"Failed to initialize Slither for target {target}: {exc}")
            return findings

        try:
            # Register all available detectors
            if _DetectorAll is not None and _AbstractDetector is not None:
                for detector_name in dir(_DetectorAll):
                    detector_cls = getattr(_DetectorAll, detector_name)
                    if (
                        isinstance(detector_cls, type)
                        and issubclass(detector_cls, _AbstractDetector)
                        and detector_cls != _AbstractDetector
                    ):
                        slither.register_detector(detector_cls)

            # Run all built-in detectors; use the public run_detectors() API
            results = slither.run_detectors()  # type: ignore
            # Flatten results (run_detectors returns list of lists)
            flat_results = []
            for r in results:
                if isinstance(r, list):
                    flat_results.extend(r)
                elif r is not None:
                    flat_results.append(r)
            results = flat_results
        except Exception as exc:
            # Gracefully handle compilation/runtime issues
            logger.error(f"Slither run_detectors() failed for {target}: {exc}")
            return findings

        if not results:
            return findings

        for res in results:
            finding = _convert_result(res, target)
            if finding:
                findings.append(finding)

        # Ensure fingerprint for each finding exists
        for f in findings:
            if not getattr(f, "fingerprint", None):
                f.compute_fingerprint()

        return findings


def _map_severity(impact: Optional[str]) -> FindingSeverity:
    if impact is None:
        return FindingSeverity.MEDIUM
    s = str(impact).lower()
    if "critical" in s:
        return FindingSeverity.CRITICAL
    if "high" in s:
        return FindingSeverity.HIGH
    if "medium" in s:
        return FindingSeverity.MEDIUM
    if "low" in s:
        return FindingSeverity.LOW
    if "info" in s:
        return FindingSeverity.INFO
    return FindingSeverity.MEDIUM


def _map_confidence(conf: Optional[str]) -> FindingConfidence:
    if conf is None:
        return FindingConfidence.MEDIUM
    s = str(conf).lower()
    if "high" in s:
        return FindingConfidence.HIGH
    if "medium" in s:
        return FindingConfidence.MEDIUM
    if "low" in s:
        return FindingConfidence.LOW
    return FindingConfidence.MEDIUM


def _extract_location(data: dict, file_path: str) -> SourceLocation:
    start_line = 1
    # Try common shapes for line information
    if isinstance(data.get("location"), dict):
        ll = data["location"].get("start_line") or data["location"].get("line")
        if ll is not None:
            try:
                start_line = int(ll)
            except Exception:
                start_line = 1
    elif isinstance(data.get("start_line"), int):
        start_line = int(data.get("start_line"))
    elif isinstance(data.get("locations"), list) and data["locations"]:
        first = data["locations"][0]
        ll = first.get("start_line") or first.get("line")
        if ll is not None:
            try:
                start_line = int(ll)
            except Exception:
                start_line = 1
    return SourceLocation(file=file_path, start_line=start_line)


def _convert_result(res: object, target: str) -> Optional[Finding]:
    # Normalize to a dict-like structure
    data: dict
    if isinstance(res, dict):
        data = res
    else:
        try:
            data = getattr(res, "to_dict", lambda: {})() or getattr(res, "__dict__", {})  # type: ignore
        except Exception:
            data = {}

    # Extract fields with sensible fallbacks
    rule_id = (
        data.get("rule_id")
        or data.get("name")
        or data.get("detector")
        or data.get("id")
        or "slither.detector"
    )
    description = data.get("description") or data.get("message") or data.get("detail") or str(data)
    impact = data.get("impact") or data.get("severity") or data.get("score")
    confidence = data.get("confidence") or data.get("confidence_level") or None

    location = _extract_location(data, target)

    title = data.get("title") or rule_id or "Slither Finding"

    severity = _map_severity(impact)
    conf = _map_confidence(confidence)

    finding = Finding(
        tool="slither",
        rule_id=str(rule_id),
        severity=severity,
        confidence=conf,
        title=str(title),
        description=str(description),
        location=location,
    )

    # Optional fields
    code_snippet = data.get("code") or data.get("source")
    if code_snippet:
        finding.code_snippet = str(code_snippet)
    recommendation = data.get("recommendation") or data.get("fix")
    if recommendation:
        finding.recommendation = str(recommendation)
    references = data.get("references") or data.get("url") or []
    if isinstance(references, list):
        finding.references = [str(x) for x in references]

    # Compute fingerprint if not present
    if not finding.fingerprint:
        finding.compute_fingerprint()

    return finding

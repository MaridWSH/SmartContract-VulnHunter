"""Format scanner findings into structured LLM-digestible context."""

from __future__ import annotations

from typing import Any, Dict, List

from vulnhunter.models.finding import Finding


def format_scanner_findings_for_llm(findings: List[Finding]) -> str:
    """Render scanner findings as a structured markdown block for LLM prompts.

    Groups by multi-scanner agreement to signal confidence.
    """
    if not findings:
        return ""

    # Group by fingerprint for agreement detection
    by_fingerprint: Dict[str, List[Finding]] = {}
    for f in findings:
        fp = getattr(f, "fingerprint", None) or f"{f.rule_id}:{f.location.file}:{f.location.start_line}"
        by_fingerprint.setdefault(fp, []).append(f)

    multi: List[str] = []
    single: List[str] = []

    for fp, group in by_fingerprint.items():
        tools = sorted({f.tool for f in group})
        f = group[0]
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        line = (
            f"- [{', '.join(tools)}] {f.rule_id} in {f.location.file}:{f.location.start_line}"
            f' — "{f.description[:120]}"'
        )
        if len(tools) >= 2:
            multi.append(line)
        else:
            single.append(line)

    parts = [
        "# Deterministic Scanner Findings",
        "(These are mechanical findings from static analyzers. Treat as hints, not ground truth.",
        "Many will be false positives; some will be real. Your job is to validate each.)",
        "",
    ]

    if multi:
        parts.append("## High-confidence findings (detected by ≥2 scanners)")
        parts.extend(multi)
        parts.append("")

    if single:
        parts.append("## Single-scanner findings")
        parts.extend(single)
        parts.append("")

    return "\n".join(parts)

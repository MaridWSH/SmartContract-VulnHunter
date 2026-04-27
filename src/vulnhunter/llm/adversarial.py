"""Adversarial verification pass for VulnHunter.

A dedicated devil's-advocate pass that receives all findings from the 6-pass
pipeline and tries to refute each one. Uses Claude Sonnet 4.6 via the anthropic SDK.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from anthropic import Anthropic

from vulnhunter.models.finding import Finding, FindingSeverity


class VerifiedFinding:
    def __init__(self, finding: Finding, verdict: str, reasoning: str, confidence: float):
        self.finding = finding
        self.verdict = verdict
        self.reasoning = reasoning
        self.confidence = confidence


class AdversarialVerifier:
    """Verifies findings by asking Claude to refute them."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-sonnet-20240229"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self._client: Optional[Anthropic] = None

    def _get_client(self) -> Anthropic:
        if self._client is None:
            if not self.api_key:
                raise RuntimeError(
                    "Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass api_key."
                )
            self._client = Anthropic(api_key=self.api_key)
        return self._client

    def _build_verification_prompt(
        self,
        finding: Finding,
        code: str,
        context: Dict[str, Any],
    ) -> str:
        recon_summary = ""
        if context.get("recon"):
            recon = context["recon"]
            recon_summary = (
                f"Protocol: {recon.protocol_type or 'unknown'}\n"
                f"Ecosystems: {', '.join(recon.ecosystems) if recon.ecosystems else 'unknown'}\n"
                f"Build: {recon.build_status}\n"
            )

        return f"""You are a skeptical auditor whose job is to refute the following finding.

Your task is to carefully examine the finding, the code, and the context, then decide whether the finding is valid.

Be aggressive in your skepticism. Look for:
- False positives from pattern matching
- Missing preconditions or guards
- Code that actually handles the case described
- Misunderstood semantics or business logic
- Incorrect line numbers or function references

## Finding

- **Title**: {finding.title}
- **Severity**: {finding.severity.value if hasattr(finding.severity, 'value') else finding.severity}
- **Description**: {finding.description}
- **Location**: {finding.location.file}:{finding.location.start_line}

## Code Context

```solidity
{code[:8000]}
```

## Recon Summary

{recon_summary}

## Output Format

Respond with a single JSON object (no markdown, no prose outside JSON):

```json
{{
  "verdict": "confirmed" | "refuted" | "uncertain",
  "reasoning": "Detailed explanation of your assessment",
  "confidence": 0.0 to 1.0
}}
```

- "confirmed": The finding is a genuine security issue.
- "refuted": The finding is a false positive or incorrect.
- "uncertain": You cannot confidently confirm or refute.

Be thorough. Your goal is to catch false positives."""

    async def verify(
        self,
        findings: List[Finding],
        code: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[VerifiedFinding]:
        """Verify each finding independently."""
        ctx = context or {}
        verified: List[VerifiedFinding] = []

        for finding in findings:
            try:
                prompt = self._build_verification_prompt(finding, code, ctx)
                result = await self._call_claude(prompt)
                verdict = result.get("verdict", "uncertain")
                reasoning = result.get("reasoning", "No reasoning provided")
                confidence = float(result.get("confidence", 0.5))

                verified.append(
                    VerifiedFinding(
                        finding=finding,
                        verdict=verdict,
                        reasoning=reasoning,
                        confidence=confidence,
                    )
                )
            except Exception as e:
                # On failure, keep as uncertain
                verified.append(
                    VerifiedFinding(
                        finding=finding,
                        verdict="uncertain",
                        reasoning=f"Verification error: {e}",
                        confidence=0.0,
                    )
                )

        return verified

    async def _call_claude(self, prompt: str) -> Dict[str, Any]:
        client = self._get_client()

        import asyncio

        def _call():
            resp = client.messages.create(
                model=self.model,
                max_tokens=1024,
                temperature=0.1,
                system="You are a skeptical security auditor. Your job is to find flaws in vulnerability findings and refute false positives.",
                messages=[{"role": "user", "content": prompt}],
            )
            content = resp.content[0].text if resp.content else ""
            return content

        raw = await asyncio.to_thread(_call)
        return parse_json_safely(raw)


def _normalize_severity(value: Any) -> Optional[FindingSeverity]:
    """Convert a severity string or enum to FindingSeverity."""
    if isinstance(value, FindingSeverity):
        return value
    if isinstance(value, str):
        mapping = {
            "critical": FindingSeverity.CRITICAL,
            "high": FindingSeverity.HIGH,
            "medium": FindingSeverity.MEDIUM,
            "low": FindingSeverity.LOW,
            "info": FindingSeverity.INFO,
        }
        return mapping.get(value.lower())
    return None


def apply_verdicts(
    findings: List[Finding],
    verified: List[VerifiedFinding],
) -> List[Finding]:
    """Drop refuted findings and demote uncertain ones by one severity level."""
    result: List[Finding] = []
    severity_order = [
        FindingSeverity.CRITICAL,
        FindingSeverity.HIGH,
        FindingSeverity.MEDIUM,
        FindingSeverity.LOW,
        FindingSeverity.INFO,
    ]

    for vf in verified:
        if vf.verdict == "refuted":
            continue
        finding = vf.finding
        if vf.verdict == "uncertain":
            # Demote one severity level
            sev = _normalize_severity(finding.severity)
            if sev is not None:
                current_idx = severity_order.index(sev)
                if current_idx < len(severity_order) - 1:
                    finding.severity = severity_order[current_idx + 1]
        result.append(finding)

    return result


def parse_json_safely(text: str) -> Dict[str, Any]:
    """Best-effort JSON parse; returns empty dict on failure."""
    try:
        return json.loads(text)  # type: ignore[return-value]
    except Exception:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1:
            try:
                return json.loads(text[start : end + 1])  # type: ignore[return-value]
            except Exception:
                pass
        return {}

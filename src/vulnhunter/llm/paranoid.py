"""Paranoid hypothesis pattern — forced-assumption vulnerability scanning.

For each code segment × vulnerability class, assume the vulnerability IS present
and force the LLM to localize it. This catches bugs open-ended prompts miss.
"""

from __future__ import annotations

import asyncio
import logging
from typing import List, Optional

from vulnhunter.parsing.models import CodeSegment
from vulnhunter.knowledge.attack_vectors import AttackVector

logger = logging.getLogger(__name__)


class Hypothesis:
    def __init__(
        self,
        segment: CodeSegment,
        vector: AttackVector,
        confidence: float,
        reasoning: str,
        location_hint: str = "",
    ):
        self.segment = segment
        self.vector = vector
        self.confidence = confidence
        self.reasoning = reasoning
        self.location_hint = location_hint


class ParanoidScanner:
    """Scan code segments with forced-assumption prompting."""

    def __init__(self, router=None):
        from .router import ModelRouter
        self.router = router or ModelRouter()

    async def scan(
        self,
        segments: List[CodeSegment],
        vuln_classes: List[AttackVector],
    ) -> List[Hypothesis]:
        """Run paranoid scan on segments × vuln_classes."""
        hypotheses: List[Hypothesis] = []

        # Filter: only externally callable or payable functions
        target_segments = [
            s for s in segments
            if s.kind == "function" and (s.declared_visibility in ("public", "external") or s.is_payable)
        ]

        # Filter: limit to 20 most relevant vuln classes
        target_vectors = vuln_classes[:20]

        # First-pass filter with Kimi (cheap)
        plausible = await self._first_pass_filter(target_segments, target_vectors)

        # Deep analysis with Claude for plausible pairs
        for segment, vector in plausible:
            try:
                hyp = await self._deep_analyze(segment, vector)
                if hyp and hyp.confidence >= 0.3:
                    hypotheses.append(hyp)
            except Exception as exc:
                logger.warning(f"Paranoid deep analysis failed: {exc}")

        return hypotheses

    async def _first_pass_filter(
        self, segments: List[CodeSegment], vectors: List[AttackVector]
    ) -> List[tuple[CodeSegment, AttackVector]]:
        """Quick filter: is this (segment, vector) pair remotely plausible?"""
        plausible = []
        client = self.router.for_pass("recon")

        for segment in segments[:30]:  # Cap segments
            for vector in vectors:
                prompt = f"""Is a {vector.name} vulnerability plausible in this function?
Answer ONLY "yes" or "no".

Function: {segment.name}
Code:
```solidity
{segment.source[:800]}
```
"""
                try:
                    raw = await client.analyze(prompt, max_tokens=10)
                    if "yes" in raw.lower():
                        plausible.append((segment, vector))
                except Exception:
                    pass

        return plausible

    async def _deep_analyze(
        self, segment: CodeSegment, vector: AttackVector
    ) -> Optional[Hypothesis]:
        """Deep analysis with Claude Sonnet."""
        client = self.router.for_pass("scan")

        prompt = f"""Assume a {vector.name} vulnerability IS present in the following code.
Show me exactly where and how. If after thorough analysis you cannot find it, state that clearly with reasoning.

Attack vector details: {vector.description}
Pattern hints: {'; '.join(vector.pattern_hints)}

```solidity
{segment.source[:2000]}
```

Respond with JSON:
{{
  "found": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "...",
  "location_hint": "line numbers or function names"
}}
"""
        try:
            raw = await client.analyze(prompt, max_tokens=1024)
            import json
            try:
                data = json.loads(raw)
            except Exception:
                # Try to extract JSON substring
                start = raw.find("{")
                end = raw.rfind("}")
                if start != -1 and end != -1:
                    data = json.loads(raw[start:end+1])
                else:
                    return None

            if data.get("found"):
                return Hypothesis(
                    segment=segment,
                    vector=vector,
                    confidence=float(data.get("confidence", 0.5)),
                    reasoning=data.get("reasoning", ""),
                    location_hint=data.get("location_hint", ""),
                )
        except Exception as exc:
            logger.warning(f"Deep analysis failed for {segment.name}: {exc}")

        return None

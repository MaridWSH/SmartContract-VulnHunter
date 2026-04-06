"""6-pass Kimi-based vulnhunter analysis pipeline.

This module orchestrates the six passes, manages a small in-process context
cache to reduce repeated work, and aggregates per-pass results into a final
structured AnalysisResult.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .client import KimiClient
from .prompts import build_pass_prompt, context_key, trim_context, parse_json_safely  # type: ignore


@dataclass
class Finding:
    id: str
    description: str
    severity: str
    location: str
    evidence: str = ""


@dataclass
class AnalysisResult:
    passes: Dict[int, Any] = field(default_factory=dict)
    context_version: int = 1
    summary: str = "6-pass vulnhunter analysis completed"


class AnalysisPipeline:
    def __init__(self, client: KimiClient):
        self.client = client
        self._cache: Dict[str, Any] = {}
        # budgets in tokens per pass (approximate)
        self._budgets: Dict[int, int] = {
            1: 800,
            2: 1000,
            3: 900,
            4: 1100,
            5: 900,
            6: 700,
        }

    async def run_pass(
        self, pass_number: int, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        # Build prompt for this pass and respect per-pass budget
        prompt = build_pass_prompt(pass_number, context)
        code = context.get("code", "")
        # Maintain the 256KB window for grounding
        prompt_trimmed_code = trim_context(code, 256 * 1024)
        context["code"] = prompt_trimmed_code

        # Context cache key
        key = context_key(prompt_trimmed_code, pass_number)
        if key in self._cache:
            return self._cache[key]

        max_tokens = self._budgets.get(pass_number)
        # Call the LLM
        raw = await self.client.analyze(prompt, max_tokens=max_tokens)
        parsed = None
        if isinstance(raw, str):
            parsed = parse_json_safely(raw)
        else:
            parsed = raw
        # Cache and return
        self._cache[key] = parsed
        return parsed

    async def analyze_findings(
        self, findings: List[Finding], code: str
    ) -> AnalysisResult:
        # Initialize a light context
        context: Dict[str, Any] = {
            "code": trim_context(code, 256 * 1024),
            "findings": [f.__dict__ for f in findings],
        }
        results: Dict[int, Any] = {}
        for pass_number in range(1, 7):
            res = await self.run_pass(pass_number, context)
            results[pass_number] = res
            # Update context with the latest findings for grounding subsequent passes
            context["found_in_pass_" + str(pass_number)] = res
            # Keep a lightweight structure for the next passes
            context["findings"].append({"pass": pass_number, "result": res})

        return AnalysisResult(
            passes=results,
            context_version=1,
            summary="6-pass vulnhunter analysis completed",
        )

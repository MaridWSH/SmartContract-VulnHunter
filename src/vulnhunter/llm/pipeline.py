"""6-pass Kimi-based vulnhunter analysis pipeline.

This module orchestrates the six passes, manages a small in-process context
cache to reduce repeated work, and aggregates per-pass results into a final
structured AnalysisResult.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .client import KimiClient
from .prompts import build_pass_prompt, context_key, trim_context, parse_json_safely  # type: ignore
from vulnhunter.recon.engine import ReconEngine
from vulnhunter.recon.models.recon_report import ReconReport


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
    verified_findings: List[Finding] = field(default_factory=list)
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

        # Optional: Enrich prompt with scanner findings context
        scanner_findings = context.get("scanner_findings", [])
        if scanner_findings:
            try:
                from .scanner_context import format_scanner_findings_for_llm
                scanner_text = format_scanner_findings_for_llm(scanner_findings)
                if scanner_text:
                    prompt = f"{scanner_text}\n\n{prompt}"
            except Exception:
                pass

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
        self,
        findings: List[Finding],
        code: str,
        recon_report: Optional[ReconReport] = None,
        target_path: Optional[str] = None,
    ) -> AnalysisResult:
        # Auto-run recon if not provided and target path is available
        recon = recon_report
        if recon is None and target_path is not None:
            cache_path = Path(target_path) / ".vulnhunter" / "recon-report.json"
            if cache_path.exists():
                try:
                    recon = ReconReport.model_validate_json(cache_path.read_text())
                except Exception:
                    recon = None
            if recon is None:
                engine = ReconEngine(target_path)
                recon = await engine.run_recon()
                try:
                    cache_path.parent.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(recon.model_dump_json(indent=2))
                except Exception:
                    pass

        # Initialize a light context
        context: Dict[str, Any] = {
            "code": trim_context(code, 256 * 1024),
            "findings": [f.__dict__ for f in findings],
        }
        if recon is not None:
            context["recon"] = recon

        # Optional: Code segmentation for large files
        segments = self._segment_code(code)
        if segments:
            context["segments"] = segments

        results: Dict[int, Any] = {}
        for pass_number in range(1, 7):
            res = await self.run_pass(pass_number, context)
            results[pass_number] = res
            # Update context with the latest findings for grounding subsequent passes
            context["found_in_pass_" + str(pass_number)] = res
            # Keep a lightweight structure for the next passes
            context["findings"].append({"pass": pass_number, "result": res})

        # Pass 7: Adversarial verification
        if findings:
            from .adversarial import AdversarialVerifier, apply_verdicts

            verifier = AdversarialVerifier()
            try:
                verified = await verifier.verify(findings, code, context)
                findings = apply_verdicts(findings, verified)
            except Exception:
                pass

        # Optional: Paranoid hypothesis scanning
        findings = await self._run_paranoid_scan(findings, code, context)

        # Optional: Multi-model consensus voting
        findings = await self._run_consensus_vote(findings, code, context)

        return AnalysisResult(
            passes=results,
            verified_findings=findings,
            context_version=1,
            summary="6-pass vulnhunter analysis completed",
        )

    def _segment_code(self, code: str) -> List[Dict[str, Any]]:
        """Segment code using tree-sitter if available."""
        try:
            from vulnhunter.parsing.segmenter import CodeSegmenter
            segmenter = CodeSegmenter()
            return segmenter.segment(code, language="solidity")
        except Exception:
            return []

    async def _run_paranoid_scan(
        self, findings: List[Finding], code: str, context: Dict[str, Any]
    ) -> List[Finding]:
        """Run paranoid scanner to catch missed vulnerabilities."""
        try:
            from .paranoid import ParanoidScanner
            scanner = ParanoidScanner()
            extra = await scanner.scan(code, context)
            if extra:
                findings = findings + extra
        except Exception:
            pass
        return findings

    async def _run_consensus_vote(
        self, findings: List[Finding], code: str, context: Dict[str, Any]
    ) -> List[Finding]:
        """Run consensus voting across multiple models for high-confidence findings."""
        try:
            from .consensus import ConsensusScanner
            from .router import ModelRouter
            router = ModelRouter()
            consensus = ConsensusScanner(router=router)
            findings = await consensus.vote(findings, code, context)
        except Exception:
            pass
        return findings

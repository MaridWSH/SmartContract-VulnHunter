"""LangGraph orchestration for VulnHunter analysis pipeline.

Replaces the sequential 6-pass pipeline with a directed graph that supports:
- Parallel scanning agents (4 groups)
- Model tiering per node
- Checkpointing for crash recovery
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from vulnhunter.models.finding import Finding
from vulnhunter.recon.models.recon_report import ReconReport

logger = logging.getLogger(__name__)


class PipelineState(BaseModel):
    """Shared state schema for the LangGraph pipeline."""

    recon_report: Optional[ReconReport] = None
    scanner_findings: List[Finding] = Field(default_factory=list)
    llm_findings_by_group: Dict[int, List[Finding]] = Field(default_factory=dict)
    merged_findings: List[Finding] = Field(default_factory=list)
    verified_findings: List[Finding] = Field(default_factory=list)
    synthesized_findings: List[Finding] = Field(default_factory=list)
    pocs: Dict[str, str] = Field(default_factory=dict)
    final_findings: List[Finding] = Field(default_factory=list)
    target_path: Optional[str] = None
    code: str = ""
    config: Dict[str, Any] = Field(default_factory=dict)
    telemetry: Dict[str, Any] = Field(default_factory=dict)


@dataclass
class GraphResult:
    passes: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    summary: str = "LangGraph pipeline completed"


class VulnHunterGraph:
    """LangGraph-based analysis pipeline.

    Architecture:
      recon -> [scan_g1, scan_g2, scan_g3, scan_g4] -> dedup -> adversarial -> synthesis -> poc -> output
    """

    def __init__(self, router=None, telemetry=None):
        from .router import ModelRouter
        from .telemetry import CostTracker

        self.router = router or ModelRouter()
        self.telemetry = telemetry or CostTracker()
        self._graph = self._build_graph()

    def _build_graph(self):
        try:
            from langgraph.graph import StateGraph, END
            from langgraph.checkpoint.sqlite import SqliteSaver

            builder = StateGraph(PipelineState)

            builder.add_node("recon", self._node_recon)
            builder.add_node("scan_g1", self._node_scan_g1)
            builder.add_node("scan_g2", self._node_scan_g2)
            builder.add_node("scan_g3", self._node_scan_g3)
            builder.add_node("scan_g4", self._node_scan_g4)
            builder.add_node("dedup", self._node_dedup)
            builder.add_node("adversarial", self._node_adversarial)
            builder.add_node("synthesis", self._node_synthesis)
            builder.add_node("poc", self._node_poc)
            builder.add_node("output", self._node_output)

            builder.set_entry_point("recon")
            for node in ["scan_g1", "scan_g2", "scan_g3", "scan_g4"]:
                builder.add_edge("recon", node)
            for node in ["scan_g1", "scan_g2", "scan_g3", "scan_g4"]:
                builder.add_edge(node, "dedup")
            builder.add_edge("dedup", "adversarial")
            builder.add_edge("adversarial", "synthesis")
            builder.add_edge("synthesis", "poc")
            builder.add_edge("poc", "output")
            builder.add_edge("output", END)

            # Checkpointing for crash recovery
            import os
            os.makedirs(".vulnhunter", exist_ok=True)
            checkpointer = SqliteSaver.from_conn_string(".vulnhunter/checkpoints.sqlite").__enter__()
            return builder.compile(checkpointer=checkpointer)
        except ImportError as exc:
            logger.warning(f"LangGraph not available: {exc}")
            return None

    async def run(self, state: PipelineState) -> GraphResult:
        if self._graph is None:
            return await self._fallback_run(state)

        try:
            result = await self._graph.ainvoke(state.model_dump())
            final_state = PipelineState(**result)
            return GraphResult(
                passes={},
                findings=final_state.final_findings,
                summary="LangGraph pipeline completed",
            )
        except Exception as exc:
            logger.warning(f"LangGraph run failed: {exc}; falling back to sequential")
            return await self._fallback_run(state)

    async def _fallback_run(self, state: PipelineState) -> GraphResult:
        """Sequential fallback when LangGraph is unavailable."""
        logger.info("Running sequential fallback pipeline")
        from .pipeline import AnalysisPipeline
        from .client import KimiClient

        client = KimiClient(api_key="", model="kimi-k2.5")
        pipeline = AnalysisPipeline(client)
        result = await pipeline.analyze_findings(
            findings=[],
            code=state.code,
            recon_report=state.recon_report,
            target_path=state.target_path,
        )
        return GraphResult(
            passes=result.passes,
            findings=result.verified_findings,
            summary="Sequential fallback completed",
        )

    # Node implementations

    async def _node_recon(self, state: PipelineState) -> PipelineState:
        if state.recon_report is None and state.target_path:
            from vulnhunter.recon.engine import ReconEngine

            engine = ReconEngine(state.target_path)
            state.recon_report = await engine.run_recon()
        return state

    async def _node_scan(self, state: PipelineState, group: int) -> PipelineState:
        """Generic scanning node for attack vector group N."""
        from vulnhunter.knowledge.attack_vectors import load_attack_vectors

        vectors = load_attack_vectors()
        group_vectors = vectors.get(group, [])

        if not group_vectors or not state.code:
            state.llm_findings_by_group[group] = []
            return state

        client = self.router.for_pass("scan")
        prompt = self._build_scan_prompt(state.code, group_vectors, state.recon_report)

        try:
            raw = await client.analyze(prompt, max_tokens=1500)
            findings = self._parse_llm_findings(raw, group)
            state.llm_findings_by_group[group] = findings
        except Exception as exc:
            logger.warning(f"Scan group {group} failed: {exc}")
            state.llm_findings_by_group[group] = []

        return state

    async def _node_scan_g1(self, state: PipelineState) -> PipelineState:
        return await self._node_scan(state, 1)

    async def _node_scan_g2(self, state: PipelineState) -> PipelineState:
        return await self._node_scan(state, 2)

    async def _node_scan_g3(self, state: PipelineState) -> PipelineState:
        return await self._node_scan(state, 3)

    async def _node_scan_g4(self, state: PipelineState) -> PipelineState:
        return await self._node_scan(state, 4)

    async def _node_dedup(self, state: PipelineState) -> PipelineState:
        all_findings: List[Finding] = []
        for group_findings in state.llm_findings_by_group.values():
            all_findings.extend(group_findings)

        # Simple dedup by fingerprint
        seen: set[str] = set()
        unique: List[Finding] = []
        for f in all_findings:
            fp = getattr(f, "fingerprint", None) or f.rule_id
            if fp not in seen:
                seen.add(fp)
                unique.append(f)

        state.merged_findings = unique
        return state

    async def _node_adversarial(self, state: PipelineState) -> PipelineState:
        if not state.merged_findings:
            state.verified_findings = []
            return state

        try:
            from .adversarial import AdversarialVerifier, apply_verdicts

            client = self.router.for_pass("adversarial")
            verifier = AdversarialVerifier(
                api_key=getattr(client, "api_key", None),
                model=getattr(client, "model", "claude-opus-4-7"),
            )
            verified = await verifier.verify(
                state.merged_findings, state.code, {"recon": state.recon_report}
            )
            state.verified_findings = apply_verdicts(state.merged_findings, verified)
        except Exception as exc:
            logger.warning(f"Adversarial pass failed: {exc}")
            state.verified_findings = state.merged_findings

        return state

    async def _node_synthesis(self, state: PipelineState) -> PipelineState:
        if not state.verified_findings:
            state.synthesized_findings = []
            return state

        client = self.router.for_pass("synthesis")
        prompt = self._build_synthesis_prompt(state.verified_findings, state.scanner_findings)

        try:
            raw = await client.analyze(prompt, max_tokens=2000)
            # Synthesis doesn't produce new findings; it enriches existing ones
            state.synthesized_findings = state.verified_findings
        except Exception as exc:
            logger.warning(f"Synthesis failed: {exc}")
            state.synthesized_findings = state.verified_findings

        return state

    async def _node_poc(self, state: PipelineState) -> PipelineState:
        # PoC generation placeholder
        state.pocs = {}
        return state

    async def _node_output(self, state: PipelineState) -> PipelineState:
        state.final_findings = state.synthesized_findings
        return state

    # Prompt builders

    def _build_scan_prompt(
        self, code: str, vectors: List[Any], recon: Optional[ReconReport]
    ) -> str:
        vector_text = "\n".join(f"- {v.name}: {v.description}" for v in vectors[:10])
        recon_text = ""
        if recon:
            recon_text = f"Protocol: {recon.protocol_type or 'unknown'}\n"
        return f"""Analyze the following code for vulnerabilities.

{recon_text}
Attack vectors to focus on:
{vector_text}

```solidity
{code[:12000]}
```

Report any findings as JSON array with fields: title, description, severity, location.
"""

    def _build_synthesis_prompt(
        self, findings: List[Finding], scanner_findings: List[Finding]
    ) -> str:
        finding_text = "\n".join(
            f"- {f.title} ({f.severity}): {f.description[:100]}"
            for f in findings[:20]
        )
        return f"""Synthesize the following findings and cross-reference with scanner output.

LLM Findings:
{finding_text}

Provide a consolidated analysis with confidence scores.
"""

    def _parse_llm_findings(self, raw: str, group: int) -> List[Finding]:
        """Best-effort parse of LLM JSON output into Findings."""
        import json

        try:
            data = json.loads(raw)
            if isinstance(data, list):
                results = []
                for item in data:
                    if isinstance(item, dict):
                        from vulnhunter.models.finding import FindingSeverity, SourceLocation

                        sev = item.get("severity", "medium").lower()
                        severity = FindingSeverity(sev) if sev in {"critical", "high", "medium", "low", "info"} else FindingSeverity.MEDIUM
                        loc = item.get("location", "unknown:1")
                        if isinstance(loc, str) and ":" in loc:
                            file_part, line_part = loc.rsplit(":", 1)
                            try:
                                line = int(line_part)
                            except ValueError:
                                line = 1
                        else:
                            file_part = "unknown"
                            line = 1

                        f = Finding(
                            tool=f"llm_group_{group}",
                            rule_id=item.get("title", "unknown").lower().replace(" ", "_"),
                            severity=severity,
                            confidence="medium",
                            title=item.get("title", "LLM Finding"),
                            description=item.get("description", ""),
                            location=SourceLocation(file=file_part, start_line=line),
                        )
                        f.compute_fingerprint()
                        results.append(f)
                return results
        except Exception:
            pass
        return []

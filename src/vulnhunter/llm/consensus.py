"""Multi-model consensus voting for findings."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

from .clients.base import LLMClient

logger = logging.getLogger(__name__)


@dataclass
class ConsensusResult:
    finding_key: str
    title: str
    confidence_ratio: float  # models reporting / total models
    models: List[str]
    severity: str


class ConsensusScanner:
    """Run the same prompt across multiple models and vote on findings."""

    async def scan(
        self, prompt: str, models: List[LLMClient]
    ) -> List[ConsensusResult]:
        """Run prompt on all models concurrently and merge findings."""
        if not models:
            return []

        results = await asyncio.gather(
            *[self._run_model(m, prompt) for m in models],
            return_exceptions=True,
        )

        all_findings: Dict[str, List[str]] = {}
        model_names = []

        for client, raw in zip(models, results):
            if isinstance(raw, Exception):
                logger.warning(f"Model {client.model_name} failed: {raw}")
                continue
            model_names.append(client.model_name)
            for finding in raw:
                key = finding.get("title", "unknown")
                all_findings.setdefault(key, []).append(client.model_name)

        consensus: List[ConsensusResult] = []
        for key, reporters in all_findings.items():
            ratio = len(reporters) / len(models)
            consensus.append(
                ConsensusResult(
                    finding_key=key,
                    title=key,
                    confidence_ratio=ratio,
                    models=reporters,
                    severity="medium",
                )
            )

        # Sort by confidence
        consensus.sort(key=lambda x: x.confidence_ratio, reverse=True)
        return consensus

    async def _run_model(self, client: LLMClient, prompt: str) -> List[Dict]:
        try:
            raw = await client.analyze(prompt, max_tokens=1500)
            import json
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and "findings" in data:
                    return data["findings"]
            except Exception:
                pass
            return []
        except Exception as exc:
            logger.warning(f"Consensus model {client.model_name} error: {exc}")
            return []

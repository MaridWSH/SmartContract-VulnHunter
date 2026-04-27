"""Anthropic Claude client (async)."""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from .base import LLMClient
from ..telemetry import CostTracker


class ClaudeClient(LLMClient):
    """Claude via Anthropic SDK."""

    # Pricing circa early 2026 (per 1M tokens)
    PRICE_INPUT_PER_1M = 3.00
    PRICE_OUTPUT_PER_1M = 15.00

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6-20251001",
        telemetry: Optional[CostTracker] = None,
    ):
        self.api_key = api_key
        self.model = model
        self._telemetry = telemetry
        self._client: Optional[Any] = None

    @property
    def model_name(self) -> str:
        return f"claude:{self.model}"

    def _get_client(self) -> Any:
        if self._client is None:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self.api_key)
        return self._client

    async def analyze(
        self, prompt: str, max_tokens: Optional[int] = None
    ) -> str:
        in_tok = self.count_tokens(prompt)
        client = self._get_client()
        max_tok = max_tokens or 1024

        def _call():
            resp = client.messages.create(
                model=self.model,
                max_tokens=max_tok,
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text if resp.content else ""

        content = await asyncio.to_thread(_call)
        out_tok = self.count_tokens(content)
        self._track(in_tok, out_tok)
        return content

    async def analyze_with_tools(
        self, prompt: str, tools: List[Dict[str, Any]], max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        in_tok = self.count_tokens(prompt) + self.count_tokens(json.dumps(tools))
        client = self._get_client()
        max_tok = max_tokens or 1024

        def _call():
            resp = client.messages.create(
                model=self.model,
                max_tokens=max_tok,
                temperature=0.2,
                messages=[{"role": "user", "content": prompt}],
            )
            text = resp.content[0].text if resp.content else ""
            return text

        text = await asyncio.to_thread(_call)
        try:
            result = json.loads(text)
        except Exception:
            result = {"content": text}
        out_tok = self.count_tokens(text)
        self._track(in_tok, out_tok)
        return result

    def count_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * self.PRICE_INPUT_PER_1M / 1_000_000
            + output_tokens * self.PRICE_OUTPUT_PER_1M / 1_000_000
        )

    def _track(self, input_tokens: int, output_tokens: int) -> None:
        if self._telemetry:
            self._telemetry.add_call(
                model=self.model_name,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=self.estimate_cost(input_tokens, output_tokens),
            )

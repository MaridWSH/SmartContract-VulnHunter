"""Kimi K2.5 LLM client (async, OpenAI-compatible API).

Moved from llm/client.py and conformed to the LLMClient protocol.
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from openai import OpenAI

from .base import LLMClient
from ..telemetry import CostTracker


class KimiClient(LLMClient):
    """Kimi K2.5 via OpenAI-compatible transport."""

    # Pricing circa early 2026 (per 1M tokens)
    PRICE_INPUT_PER_1M = 0.60
    PRICE_OUTPUT_PER_1M = 2.50

    def __init__(
        self,
        api_key: str,
        base_url: Optional[str] = None,
        model: str = "kimi-k2.5",
        telemetry: Optional[CostTracker] = None,
    ):
        self.client = OpenAI(
            api_key=api_key, base_url=base_url or "https://api.openai.com/v1"
        )
        self.model = model
        self._telemetry = telemetry

    @property
    def model_name(self) -> str:
        return f"kimi:{self.model}"

    async def analyze(
        self, prompt: str, max_tokens: Optional[int] = None
    ) -> str:
        in_tok = self.count_tokens(prompt)
        max_retries = 3
        backoff = 0.5
        for attempt in range(1, max_retries + 1):
            try:

                def _call():
                    return self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system",
                                "content": "You are an assistant specialized in vulnerability analysis.",
                            },
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.2,
                        max_tokens=max_tokens,
                    )

                resp = await asyncio.to_thread(_call)
                message = resp.choices[0].message
                content = self._extract_content(message)
                out_tok = self.count_tokens(content) if content else 0
                self._track(in_tok, out_tok)
                return content.strip() if content else ""
            except Exception as e:
                error_msg = str(e)
                if "rate_limit" in error_msg.lower() or "429" in error_msg:
                    if attempt == max_retries:
                        raise
                    await asyncio.sleep(backoff * (2 ** (attempt - 1)))
                    continue
                raise

    async def analyze_with_tools(
        self, prompt: str, tools: List[Dict[str, Any]], max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        in_tok = self.count_tokens(prompt) + self.count_tokens(json.dumps(tools))
        max_retries = 3
        backoff = 0.5
        for attempt in range(1, max_retries + 1):
            try:

                def _call():
                    return self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {
                                "role": "system",
                                "content": "You are an attacker hunter assistant with tool orchestration.",
                            },
                            {"role": "user", "content": prompt},
                        ],
                        temperature=0.2,
                        tools=tools,
                        tool_choice="auto",
                        max_tokens=max_tokens,
                    )

                resp = await asyncio.to_thread(_call)
                msg = resp.choices[0].message
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    fc = msg.tool_calls[0]
                    name = fc.function.name
                    args = fc.function.arguments
                    try:
                        parsed = json.loads(args)
                    except Exception:
                        parsed = {"raw": args}
                    result = {"function": name, "arguments": parsed}
                else:
                    content = getattr(msg, "content", "") or ""
                    content = content.strip()
                    try:
                        result = json.loads(content)
                    except Exception:
                        result = {"content": content}
                out_tok = self.count_tokens(json.dumps(result))
                self._track(in_tok, out_tok)
                return result
            except Exception as e:
                error_msg = str(e)
                if "rate_limit" in error_msg.lower() or "429" in error_msg:
                    if attempt == max_retries:
                        raise
                    await asyncio.sleep(backoff * (2 ** (attempt - 1)))
                    continue
                raise

    def count_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * self.PRICE_INPUT_PER_1M / 1_000_000
            + output_tokens * self.PRICE_OUTPUT_PER_1M / 1_000_000
        )

    def _extract_content(self, message: Any) -> Optional[str]:
        content = None
        if isinstance(message, dict):
            content = message.get("content")
        else:
            content = getattr(message, "content", None)
        if not content and hasattr(message, "reasoning"):
            content = message.reasoning
        if not content and hasattr(message, "model_dump"):
            msg_dict = message.model_dump()
            content = msg_dict.get("content") or msg_dict.get("reasoning")
        return content

    def _track(self, input_tokens: int, output_tokens: int) -> None:
        if self._telemetry:
            self._telemetry.add_call(
                model=self.model_name,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost_usd=self.estimate_cost(input_tokens, output_tokens),
            )

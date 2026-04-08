"""Kimi K2.5 LLM integration client (async, OpenAI-compatible API).

This module provides a light wrapper around the Kimi / Moonshot API that is
compatible with the OpenAI Chat API surface. It supports two modes:
- analyze: plain prompt execution
- analyze_with_tools: enables function calling / tool orchestration

The client is designed to be async and resilient to rate limits (HTTP 429).
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional

from openai import OpenAI


class KimiClient:
    def __init__(self, api_key: str, base_url: str = None, model: str = "kimi-k2.5"):
        # Configure OpenAI-compatible transport
        self.client = OpenAI(
            api_key=api_key, base_url=base_url if base_url else "https://api.openai.com/v1"
        )
        self.model = model

        # A very small in-process cache can be used by higher level pipeline
        # logic to reduce repeated prompts for identical inputs.
        self._inflight = set()

    async def analyze(
        self, prompt: str, model: str = None, max_tokens: Optional[int] = None
    ) -> str:
        model = model or self.model

        max_retries = 3
        backoff = 0.5
        for attempt in range(1, max_retries + 1):
            try:

                def _call():
                    return self.client.chat.completions.create(
                        model=model,
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

                # Extract content - check various possible locations
                content = None

                # Try standard content field first
                if isinstance(message, dict):
                    content = message.get("content")
                else:
                    content = getattr(message, "content", None)

                # If no content, try reasoning field (some models return reasoning)
                if not content and hasattr(message, "reasoning"):
                    content = message.reasoning

                # If still no content, try to get any text representation
                if not content and hasattr(message, "model_dump"):
                    msg_dict = message.model_dump()
                    content = msg_dict.get("content") or msg_dict.get("reasoning")

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
        self, prompt: str, tools: List[Dict[str, Any]], model: str = None
    ) -> Dict[str, Any]:
        """Run prompt with function-calling support for tool orchestration.

        The function definition is supplied as a list of JSON-Schema-like objects
        describing the available tools. The Kimi API may return a function_call
        payload which we will parse and return as a structured dict.
        """
        model = model or self.model

        max_retries = 3
        backoff = 0.5
        for attempt in range(1, max_retries + 1):
            try:

                def _call():
                    return self.client.chat.completions.create(
                        model=model,
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
                    )

                resp = await asyncio.to_thread(_call)
                msg = resp.choices[0].message
                # If the model called a function, return its payload in a structured way
                if hasattr(msg, "tool_calls") and msg.tool_calls:
                    fc = msg.tool_calls[0]
                    name = fc.function.name
                    args = fc.function.arguments
                    try:
                        parsed = json.loads(args)
                    except Exception:
                        parsed = {"raw": args}
                    return {"function": name, "arguments": parsed}
                # Otherwise, return the content as structured JSON if possible
                content = getattr(msg, "content", "") or ""
                content = content.strip()
                try:
                    return json.loads(content)
                except Exception:
                    return {"content": content}
            except Exception as e:
                error_msg = str(e)
                if "rate_limit" in error_msg.lower() or "429" in error_msg:
                    if attempt == max_retries:
                        raise
                    await asyncio.sleep(backoff * (2 ** (attempt - 1)))
                    continue
                raise

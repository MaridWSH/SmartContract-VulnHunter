"""Abstract base protocol for LLM clients.

All LLM clients (Kimi, Claude, OpenAI) implement this protocol so the
ModelRouter can switch between them transparently.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class LLMClient(ABC):
    """Protocol that all LLM clients must implement."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Human-readable model identifier."""
        pass

    @abstractmethod
    async def analyze(
        self, prompt: str, max_tokens: Optional[int] = None
    ) -> str:
        """Send a prompt and return the model's text response."""
        pass

    @abstractmethod
    async def analyze_with_tools(
        self, prompt: str, tools: List[Dict[str, Any]], max_tokens: Optional[int] = None
    ) -> Dict[str, Any]:
        """Send a prompt with function-calling support and return structured output."""
        pass

    def count_tokens(self, text: str) -> int:
        """Estimate token count for the given text.

        Default heuristic: ~4 chars per token. Override per client if
        a tokenizer is available.
        """
        return max(1, len(text) // 4)

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate USD cost for a call with given token counts.

        Override per client with model-specific pricing.
        """
        return 0.0

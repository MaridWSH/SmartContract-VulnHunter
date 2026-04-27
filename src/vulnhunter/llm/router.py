"""Model router — selects the right LLM client per pass type.

Implements model tiering: fast/cheap models for bulk work,
premium models for deep analysis.
"""

from __future__ import annotations

import logging
import os
from typing import Literal, Optional

from .clients.base import LLMClient
from .clients.kimi import KimiClient
from .telemetry import CostTracker

logger = logging.getLogger(__name__)

PassType = Literal["recon", "scan", "adversarial", "synthesis", "poc"]


class ModelRouter:
    """Routes pass types to the optimal LLM client."""

    def __init__(self, config: dict | None = None, telemetry: Optional[CostTracker] = None):
        self._config = config or {}
        self._telemetry = telemetry
        self._clients: dict[str, LLMClient] = {}
        self._routing = self._load_routing()

    def _load_routing(self) -> dict[str, str]:
        defaults = {
            "recon": "kimi",
            "scan": "claude_sonnet",
            "adversarial": "claude_opus",
            "synthesis": "openai",
            "poc": "claude_sonnet",
        }
        cfg = self._config.get("llm", {}).get("routing", {})
        return {**defaults, **cfg}

    def _get_or_create(self, key: str) -> Optional[LLMClient]:
        if key in self._clients:
            return self._clients[key]

        client = self._build_client(key)
        if client:
            self._clients[key] = client
        return client

    def _build_client(self, key: str) -> Optional[LLMClient]:
        llm_cfg = self._config.get("llm", {})

        if key == "kimi":
            cfg = llm_cfg.get("kimi", {})
            api_key = cfg.get("api_key") or os.environ.get("KIMI_API_KEY", "")
            if not api_key:
                return None
            return KimiClient(
                api_key=api_key,
                base_url=cfg.get("base_url") or None,
                model=cfg.get("model", "kimi-k2.5"),
                telemetry=self._telemetry,
            )

        if key == "claude_sonnet":
            cfg = llm_cfg.get("claude", {})
            api_key = cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                return None
            try:
                from .clients.claude import ClaudeClient
                return ClaudeClient(
                    api_key=api_key,
                    model=cfg.get("sonnet_model", "claude-sonnet-4-6-20251001"),
                    telemetry=self._telemetry,
                )
            except Exception as exc:
                logger.warning(f"Claude client unavailable: {exc}")
                return None

        if key == "claude_opus":
            cfg = llm_cfg.get("claude", {})
            api_key = cfg.get("api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
            if not api_key:
                return None
            try:
                from .clients.claude import ClaudeClient
                return ClaudeClient(
                    api_key=api_key,
                    model=cfg.get("opus_model", "claude-opus-4-7"),
                    telemetry=self._telemetry,
                )
            except Exception as exc:
                logger.warning(f"Claude client unavailable: {exc}")
                return None

        if key == "openai":
            cfg = llm_cfg.get("openai", {})
            api_key = cfg.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                return None
            try:
                from .clients.openai import OpenAIClient
                return OpenAIClient(
                    api_key=api_key,
                    model=cfg.get("model", "gpt-4o"),
                    telemetry=self._telemetry,
                )
            except Exception as exc:
                logger.warning(f"OpenAI client unavailable: {exc}")
                return None

        return None

    def for_pass(self, pass_type: PassType) -> LLMClient:
        """Return the best available client for the given pass type.

        Falls back to Kimi if the preferred provider is unavailable.
        """
        preferred = self._routing.get(pass_type, "kimi")
        client = self._get_or_create(preferred)
        if client is not None:
            return client

        # Fallback to Kimi
        logger.warning(
            f"Preferred client '{preferred}' for pass '{pass_type}' unavailable; falling back to Kimi"
        )
        fallback = self._get_or_create("kimi")
        if fallback is None:
            raise RuntimeError(
                "No LLM client available. Set at least one of: KIMI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY"
            )
        return fallback

    def available_providers(self) -> list[str]:
        """List providers that are currently configured and reachable."""
        providers = []
        for key in ["kimi", "claude_sonnet", "claude_opus", "openai"]:
            if self._get_or_create(key) is not None:
                providers.append(key)
        return providers

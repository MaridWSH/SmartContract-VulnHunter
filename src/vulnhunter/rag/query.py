"""RAG query engine for enriching LLM passes with historical findings."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from .store import VulnStore

logger = logging.getLogger(__name__)


class RAGQueryEngine:
    """Query RAG for similar historical findings to enrich analysis."""

    def __init__(self, store: Optional[VulnStore] = None):
        self.store = store or VulnStore()

    def find_similar(
        self,
        query: str,
        n: int = 5,
        filter_metadata: Optional[Dict[str, any]] = None,
    ) -> List[Dict[str, any]]:
        """Find similar historical findings."""
        return self.store.query(query, n_results=n, filter_metadata=filter_metadata)

    def enrich_finding(self, finding_title: str, finding_description: str) -> List[Dict[str, any]]:
        """Find historical examples similar to a finding."""
        query = f"{finding_title}\n{finding_description[:200]}"
        return self.find_similar(query, n=3)

    def enrich_code(self, code_snippet: str) -> List[Dict[str, any]]:
        """Find historical findings related to a code pattern."""
        return self.find_similar(code_snippet[:500], n=3)

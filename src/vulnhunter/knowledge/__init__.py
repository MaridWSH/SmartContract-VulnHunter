"""Vulnerability knowledge base module."""

from __future__ import annotations

from vulnhunter.knowledge.models.vulnerability import (
    Language,
    Severity,
    VulnerabilityEntry,
    VulnerabilityPattern,
    LanguageKnowledgeBase,
    KnowledgeBaseCategory,
    VulnerabilityKnowledgeBase,
)
from vulnhunter.knowledge.parsers.markdown import (
    VulnerabilityParser,
    KnowledgeBaseLoader,
)

__all__ = [
    "Language",
    "Severity",
    "VulnerabilityEntry",
    "VulnerabilityPattern",
    "LanguageKnowledgeBase",
    "KnowledgeBaseCategory",
    "VulnerabilityKnowledgeBase",
    "VulnerabilityParser",
    "KnowledgeBaseLoader",
]


def load_knowledge_base() -> VulnerabilityKnowledgeBase:
    """Load the complete vulnerability knowledge base.

    This is the main entry point for accessing vulnerability knowledge.
    """
    loader = KnowledgeBaseLoader()
    return loader.load_all()

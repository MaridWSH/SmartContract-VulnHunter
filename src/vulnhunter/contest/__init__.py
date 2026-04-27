"""Contest-specific submission pipeline for VulnHunter."""

from __future__ import annotations

from vulnhunter.contest.adapter import (
    ContestAdapter,
    Code4renaAdapter,
    SherlockAdapter,
    CantinaAdapter,
    CodehawksAdapter,
)
from vulnhunter.contest.pipeline import ContestPipeline

__all__ = [
    "ContestAdapter",
    "Code4renaAdapter",
    "SherlockAdapter",
    "CantinaAdapter",
    "CodehawksAdapter",
    "ContestPipeline",
]

"""Tree-sitter based code segmentation.

Splits source files into function/contract level segments for:
- Paranoid scanning (Item 14)
- RAG chunking (Item 13)
- Parallel agent code distribution (Item 9)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from .models import CodeSegment
from .languages.solidity import SoliditySegmenter

logger = logging.getLogger(__name__)


class CodeSegmenter:
    """Segment code files by language."""

    def __init__(self):
        self._solidity = SoliditySegmenter()

    def segment(self, file_path: Path) -> List[CodeSegment]:
        """Segment a single file based on its extension."""
        if not file_path.exists():
            return []

        suffix = file_path.suffix.lower()
        try:
            source = file_path.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning(f"Failed to read {file_path}: {exc}")
            return []

        if suffix == ".sol":
            return self._solidity.segment(str(file_path), source)

        # Fallback: treat whole file as one segment
        lines = source.splitlines()
        return [
            CodeSegment(
                file=str(file_path),
                start_line=1,
                end_line=len(lines),
                kind="file",
                name=file_path.stem,
                source=source,
            )
        ]

    def segment_project(self, root: Path, include: Optional[List[str]] = None) -> List[CodeSegment]:
        """Segment all matching files under root."""
        include = include or [".sol"]
        segments: List[CodeSegment] = []
        for ext in include:
            for fp in root.rglob(f"*{ext}"):
                segments.extend(self.segment(fp))
        return segments

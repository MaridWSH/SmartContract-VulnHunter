"""Solidity tree-sitter segmentation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from ..models import CodeSegment

logger = logging.getLogger(__name__)


class SoliditySegmenter:
    """Segment Solidity files using tree-sitter."""

    def __init__(self):
        self._parser = None
        self._language = None
        self._init_parser()

    def _init_parser(self) -> None:
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_solidity

            self._language = Language(tree_sitter_solidity.language())
            self._parser = Parser(self._language)
        except Exception as exc:
            logger.warning(f"tree-sitter-solidity unavailable: {exc}")
            self._parser = None

    def segment(self, file_path: str, source: str) -> List[CodeSegment]:
        if self._parser is None:
            return self._fallback_segment(file_path, source)

        try:
            tree = self._parser.parse(source.encode("utf-8"))
            root = tree.root_node
            segments: List[CodeSegment] = []
            self._walk(root, source, file_path, segments)
            return segments if segments else self._fallback_segment(file_path, source)
        except Exception as exc:
            logger.warning(f"Tree-sitter parse failed for {file_path}: {exc}")
            return self._fallback_segment(file_path, source)

    def _walk(self, node, source: str, file_path: str, segments: List[CodeSegment]) -> None:
        from tree_sitter import Node

        if node.type in ("contract_declaration", "library_declaration", "interface_declaration"):
            name_node = self._child_by_type(node, "identifier")
            name = name_node.text.decode("utf-8") if name_node else "unknown"
            seg = self._make_segment(node, source, file_path, "contract", name)
            segments.append(seg)
            for child in node.children:
                if child.type == "contract_body":
                    for member in child.children:
                        if member.type in ("function_definition", "modifier_definition"):
                            self._extract_function(member, source, file_path, segments)
            return

        for child in node.children:
            self._walk(child, source, file_path, segments)

    def _extract_function(self, node, source: str, file_path: str, segments: List[CodeSegment]) -> None:
        kind = "function" if node.type == "function_definition" else "modifier"
        name_node = self._child_by_type(node, "identifier")
        name = name_node.text.decode("utf-8") if name_node else "unknown"
        seg = self._make_segment(node, source, file_path, kind, name)
        segments.append(seg)

    def _make_segment(
        self, node, source: str, file_path: str, kind: str, name: str
    ) -> CodeSegment:
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        src = source[node.start_byte : node.end_byte]
        visibility = self._extract_visibility(node)
        payable = self._extract_payable(node)
        return CodeSegment(
            file=file_path,
            start_line=start_line,
            end_line=end_line,
            kind=kind,
            name=name,
            source=src,
            declared_visibility=visibility,
            is_payable=payable,
        )

    def _child_by_type(self, node, type_name: str):
        for child in node.children:
            if child.type == type_name:
                return child
        return None

    def _extract_visibility(self, node) -> Optional[str]:
        for child in node.children:
            if child.type in (
                "public",
                "external",
                "internal",
                "private",
            ):
                return child.type
        return None

    def _extract_payable(self, node) -> bool:
        for child in node.children:
            if child.type == "payable":
                return True
        return False

    def _fallback_segment(self, file_path: str, source: str) -> List[CodeSegment]:
        lines = source.splitlines()
        return [
            CodeSegment(
                file=file_path,
                start_line=1,
                end_line=len(lines),
                kind="file",
                name=Path(file_path).stem,
                source=source,
            )
        ]

"""Markdown vulnerability reference parser.

Parses the markdown files in vulnhunter-knowledge-base/references/
to extract structured vulnerability information.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from vulnhunter.knowledge.models.vulnerability import (
    Language,
    Severity,
    VulnerabilityEntry,
    VulnerabilityPattern,
    LanguageKnowledgeBase,
    KnowledgeBaseCategory,
)


class VulnerabilityParser:
    """Parser for vulnerability markdown references."""

    def __init__(self, language: Language):
        self.language = language

    def parse_file(self, file_path: Path) -> LanguageKnowledgeBase:
        """Parse a vulnerability reference markdown file."""
        content = file_path.read_text(encoding="utf-8")
        return self.parse_content(content)

    def parse_content(self, content: str) -> LanguageKnowledgeBase:
        """Parse markdown content into structured knowledge base."""
        kb = LanguageKnowledgeBase(language=self.language)

        lines = content.split("\n")
        current_category: Optional[str] = None
        current_entry: Optional[VulnerabilityEntry] = None
        current_section: Optional[str] = None
        section_buffer: List[str] = []

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if stripped.startswith("## ") and not stripped.startswith("###"):
                if current_entry:
                    self._flush_section(current_entry, current_section, section_buffer)
                    kb.entries.append(current_entry)

                current_category = self._clean_category(stripped[3:].strip())
                current_entry = None
                current_section = None
                section_buffer = []

            elif stripped.startswith("### "):
                if current_entry:
                    self._flush_section(current_entry, current_section, section_buffer)
                    kb.entries.append(current_entry)

                vuln_name = stripped[4:].strip()
                current_entry = self._parse_vuln_header(vuln_name, current_category or "General")
                current_section = None
                section_buffer = []

            elif stripped.startswith("#### "):
                if current_section and section_buffer:
                    self._flush_section(current_entry, current_section, section_buffer)

                current_section = stripped[5:].strip().lower()
                section_buffer = []

            elif current_entry:
                section_buffer.append(line)

            i += 1

        if current_entry:
            self._flush_section(current_entry, current_section, section_buffer)
            kb.entries.append(current_entry)

        for entry in kb.entries:
            entry.tags = self._extract_tags(entry)

        kb.categories = self._group_by_category(kb.entries)
        return kb

    def _extract_tags(self, entry: VulnerabilityEntry) -> List[str]:
        tags = [entry.category.lower().replace(" ", "-")]
        content = f"{entry.name} {entry.description} {entry.impact}".lower()

        keywords = {
            "reentrancy": "reentrancy",
            "access": "access-control",
            "oracle": "oracle",
            "price": "price-feed",
            "flash loan": "flash-loan",
            "signature": "signature",
            "proxy": "proxy",
            "upgrade": "upgrade",
            "erc20": "erc20",
            "erc721": "erc721",
            "erc1155": "erc1155",
            "delegatecall": "delegatecall",
            "assembly": "assembly",
            "rounding": "rounding",
            "dos": "dos",
            "frontrun": "frontrunning",
            "mev": "mev",
            "overflow": "overflow",
            "underflow": "underflow",
            "arithmetic": "arithmetic",
        }

        for keyword, tag in keywords.items():
            if keyword in content and tag not in tags:
                tags.append(tag)

        return tags

    def _parse_vuln_header(self, name: str, category: str) -> VulnerabilityEntry:
        """Parse vulnerability header to extract ID and severity."""
        severity = Severity.MEDIUM
        vuln_id = self._generate_id(name)

        severity_match = re.search(r"\[(Critical|High|Medium|Low|Info)\]", name, re.IGNORECASE)
        if severity_match:
            severity_str = severity_match.group(1).upper()
            try:
                severity = Severity[severity_str]
            except KeyError:
                pass
            name = re.sub(r"\s*\[.*?\]\s*", "", name)

        return VulnerabilityEntry(
            id=vuln_id,
            name=name.strip(),
            category=category,
            severity=severity,
            language=self.language,
            description="",
            impact="",
            remediation="",
        )

    def _clean_category(self, category: str) -> str:
        return re.sub(r"^\d+\.\s*", "", category)

    def _generate_id(self, name: str) -> str:
        """Generate a kebab-case ID from vulnerability name."""
        clean = re.sub(r"\[.*?\]", "", name)
        clean = re.sub(r"[^\w\s-]", "", clean)
        clean = clean.strip().lower()
        clean = re.sub(r"[-\s]+", "-", clean)
        return f"{self.language.value}-{clean[:50]}"

    def _flush_section(
        self,
        entry: Optional[VulnerabilityEntry],
        section: Optional[str],
        buffer: List[str],
    ) -> None:
        """Flush buffered content to the appropriate entry field."""
        if not entry or not section or not buffer:
            return

        content = "\n".join(buffer).strip()

        if section == "description":
            entry.description = content
        elif section == "impact":
            entry.impact = content
        elif section == "vulnerable code":
            entry.code_example = self._extract_code_block(content)
        elif section == "remediation":
            entry.remediation = content
        elif section == "remediation code":
            entry.remediation_code = self._extract_code_block(content)
        elif section == "proof of concept":
            entry.proof_of_concept = content
        elif section == "references":
            entry.references = self._extract_links(content)
        elif section == "real-world examples":
            entry.real_world_examples = self._extract_links(content)
        elif section == "affected versions":
            entry.affected_versions = content
        elif section == "detection":
            entry.affected_patterns = self._parse_patterns(content)
        elif section == "tags":
            entry.tags = [t.strip() for t in content.split(",") if t.strip()]

    def _extract_code_block(self, content: str) -> str:
        """Extract code from markdown code blocks."""
        code_block_pattern = r"```(?:\w+)?\n(.*?)```"
        matches = re.findall(code_block_pattern, content, re.DOTALL)
        if matches:
            return "\n\n".join(m.strip() for m in matches)
        return content

    def _extract_links(self, content: str) -> List[str]:
        """Extract URLs from markdown links."""
        link_pattern = r"\[([^\]]+)\]\(([^)]+)\)"
        matches = re.findall(link_pattern, content)
        return [url for _, url in matches]

    def _parse_patterns(self, content: str) -> List[VulnerabilityPattern]:
        """Parse detection patterns from content."""
        patterns = []
        lines = content.split("\n")

        current_pattern: Optional[VulnerabilityPattern] = None
        buffer: List[str] = []

        for line in lines:
            stripped = line.strip()

            if stripped.startswith("-") or stripped.startswith("*"):
                if current_pattern:
                    current_pattern.description = "\n".join(buffer).strip()
                    patterns.append(current_pattern)

                text = stripped[1:].strip()
                current_pattern = VulnerabilityPattern(name=text, description="")
                buffer = []
            else:
                buffer.append(line)

        if current_pattern:
            current_pattern.description = "\n".join(buffer).strip()
            patterns.append(current_pattern)

        return patterns

    def _group_by_category(self, entries: List[VulnerabilityEntry]) -> List[KnowledgeBaseCategory]:
        """Group entries by category."""
        categories: dict = {}
        for entry in entries:
            if entry.category not in categories:
                categories[entry.category] = []
            categories[entry.category].append(entry)

        return [
            KnowledgeBaseCategory(name=name, vulnerabilities=vulns)
            for name, vulns in categories.items()
        ]


class KnowledgeBaseLoader:
    """Loader for the complete vulnerability knowledge base."""

    REFERENCE_FILES = {
        Language.SOLIDITY: "solidity-vulns.md",
        Language.RUST: "rust-vulns.md",
        Language.VYPER: "vyper-vulns.md",
        Language.CAIRO: "cairo-vulns.md",
    }

    def __init__(self, base_path: Optional[Path] = None):
        if base_path is None:
            # Go from src/vulnhunter/knowledge/parsers/ to project root
            base_path = (
                Path(__file__).parent.parent.parent.parent.parent
                / "vulnhunter-knowledge-base"
                / "references"
            )
        self.base_path = base_path

    def load_all(self):
        """Load the complete knowledge base from all reference files."""
        from vulnhunter.knowledge.models.vulnerability import VulnerabilityKnowledgeBase

        kb = VulnerabilityKnowledgeBase()

        for language, filename in self.REFERENCE_FILES.items():
            file_path = self.base_path / filename
            if file_path.exists():
                parser = VulnerabilityParser(language)
                lang_kb = parser.parse_file(file_path)
                setattr(kb, language.value, lang_kb)

        return kb

    def load_language(self, language: Language) -> LanguageKnowledgeBase:
        """Load knowledge base for a specific language."""
        filename = self.REFERENCE_FILES.get(language)
        if not filename:
            raise ValueError(f"Unknown language: {language}")

        file_path = self.base_path / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Reference file not found: {file_path}")

        parser = VulnerabilityParser(language)
        return parser.parse_file(file_path)

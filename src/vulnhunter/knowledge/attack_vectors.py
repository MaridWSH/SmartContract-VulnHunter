from __future__ import annotations
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
import re
from pathlib import Path

class AttackVector(BaseModel):
    id: str
    group: int
    name: str
    description: str
    pattern_hints: List[str] = Field(default_factory=list)
    severity_hint: str = "Medium"

def load_attack_vectors(base_path: Optional[str] = None) -> Dict[int, List[AttackVector]]:
    """Load attack vectors from markdown files.
    Returns dict keyed by group number (1-4).
    """
    if base_path is None:
        base_path = Path(__file__).resolve().parents[3] / "vulnhunter-knowledge-base" / "attack_vectors"
    else:
        base_path = Path(base_path)
    result: Dict[int, List[AttackVector]] = {1: [], 2: [], 3: [], 4: []}

    for group_num in range(1, 5):
        file_path = base_path / f"group_{group_num}.md"
        if not file_path.exists():
            continue
        content = file_path.read_text(encoding="utf-8")
        vectors = _parse_group(content, group_num)
        result[group_num] = vectors
    return result

def _parse_group(content: str, group_num: int) -> List[AttackVector]:
    """Parse attack vectors from markdown content."""
    vectors: List[AttackVector] = []
    sections = re.split(r'\n### ', content)
    for section in sections[1:]:
        lines = section.strip().split('\n')
        if not lines:
            continue
        header = lines[0].strip()
        vector_id = f"AV-{group_num}-{len(vectors)+1}"
        name = header
        if ':' in header:
            parts = header.split(':', 1)
            vector_id = parts[0].strip()
            name = parts[1].strip()

        description = ""
        pattern_hints: List[str] = []
        severity_hint = "Medium"

        current_field = None
        for line in lines[1:]:
            line = line.strip()
            if line.startswith('- **Description**:'):
                current_field = 'description'
                description = line.split(':', 1)[1].strip()
            elif line.startswith('- **Pattern Hints**:'):
                current_field = 'pattern_hints'
                hint = line.split(':', 1)[1].strip()
                if hint:
                    pattern_hints.append(hint)
            elif line.startswith('- **Severity Hint**:'):
                current_field = 'severity_hint'
                severity_hint = line.split(':', 1)[1].strip()
            elif line.startswith('- ') and current_field == 'pattern_hints':
                pattern_hints.append(line[2:].strip())
            elif current_field == 'description' and line and not line.startswith('-'):
                description += ' ' + line
        vectors.append(AttackVector(
            id=vector_id,
            group=group_num,
            name=name,
            description=description,
            pattern_hints=pattern_hints,
            severity_hint=severity_hint,
        ))
    return vectors

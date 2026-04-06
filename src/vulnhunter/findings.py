from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Finding:
    title: str
    description: str
    severity: str
    location: str
    source: str
    raw: Optional[Any] = None

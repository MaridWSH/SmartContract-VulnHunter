from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List

from vulnhunter.findings import Finding


class ToolAdapter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def run(self, target: str) -> List[Finding]:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

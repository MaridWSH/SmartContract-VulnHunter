from abc import ABC, abstractmethod
from typing import List, Optional, Any

# Lightweight alias for runtime typing purposes. The real project
# should define a proper Finding data structure. At runtime we only
# rely on attribute access, so keeping it generic as `Any` keeps
# the reporters flexible.
Finding = Any


class BaseReporter(ABC):
    @abstractmethod
    def generate(self, findings: List[Finding], poc: Optional[str] = None) -> str:
        """Generate a markdown report for the given findings.

        Parameters:
        - findings: A list of Finding-like objects. The reporter should access
          common attributes (id/title/description/severity/funds_at_risk/poc/…)
          in a best-effort manner.
        - poc: Optional global PoC snippet or note to include when provided by the caller.
        """
        pass

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Human-friendly platform name."""
        pass

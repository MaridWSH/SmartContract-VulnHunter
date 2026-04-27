from typing import List, Optional, Dict, Any
from jinja2 import Environment, FileSystemLoader
import os
from .base import BaseReporter

Finding = Any

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


class SherlockReporter(BaseReporter):
    def __init__(self) -> None:
        self._env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

    @property
    def platform_name(self) -> str:
        return "Sherlock"

    def _normalize(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for idx, f in enumerate(findings, start=1):
            fid = getattr(f, "id", idx)
            title = getattr(f, "title", f"Finding {fid}")
            description = getattr(f, "description", "")
            # Use direct attribute access where available
            impact = f.impact if hasattr(f, "impact") else None
            # Sherlock uses impact-based severity (no likelihood)
            sev = "Low"
            matrix_score = None
            if isinstance(impact, (int, float)):
                # Simple mapping: 1-2 -> Low, 3 -> Medium, 4-5 -> High
                if impact <= 2:
                    sev = "Low"
                elif impact == 3:
                    sev = "Medium"
                else:
                    sev = "High"
            # Optional PoC per finding
            poc = getattr(f, "poc", None)
            likelihood = f.likelihood if hasattr(f, "likelihood") else None
            if isinstance(impact, (int, float)) and isinstance(
                likelihood, (int, float)
            ):
                matrix_score = int(impact * likelihood)

            normalized.append(
                {
                    "id": fid,
                    "title": title,
                    "description": description,
                    "severity": sev,
                    "impact": impact,
                    "likelihood": likelihood,
                    "matrix_score": matrix_score,
                    "poc": poc,
                }
            )
        return normalized

    def generate(self, findings: List[Finding], poc: Optional[str] = None) -> str:
        template = self._env.get_template("sherlock.md.j2")
        context = {
            "platform": self.platform_name,
            "findings": self._normalize(findings),
            "global_poc": poc,
        }
        return template.render(**context)

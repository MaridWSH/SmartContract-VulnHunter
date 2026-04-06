from typing import List, Optional, Dict, Any
from jinja2 import Environment, FileSystemLoader
from .base import BaseReporter
import os

Finding = Any


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


class ImmunefiReporter(BaseReporter):
    def __init__(self) -> None:
        self._env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

    @property
    def platform_name(self) -> str:
        return "Immunefi"

    # Simple helper to normalize a finding into a dictionary consumable by the templates
    def _normalize(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for idx, f in enumerate(findings, start=1):
            fid = getattr(f, "id", idx)
            title = getattr(f, "title", f"Finding {fid}")
            description = getattr(f, "description", "")
            funds = getattr(f, "funds_at_risk", None)
            raw_sev = getattr(f, "severity", "Info")
            poc = getattr(f, "poc", None) or None
            impact = getattr(f, "impact", None)  # optional numeric
            likelihood = getattr(f, "likelihood", None)  # optional numeric
            matrix_score = None
            if isinstance(impact, (int, float)) and isinstance(
                likelihood, (int, float)
            ):
                matrix_score = int(impact * likelihood)

            # Funds-at-risk based severity override (Immunefi pattern)
            sev = raw_sev
            if isinstance(funds, (int, float)):
                if funds >= 1_000_000:
                    sev = "Critical"
                elif funds >= 100_000:
                    sev = "High"
                elif funds >= 10_000:
                    sev = "Medium"
                elif funds >= 1_000:
                    sev = "Low"
                # else keep raw_sev

            results.append(
                {
                    "id": fid,
                    "title": title,
                    "description": description,
                    "severity": sev,
                    "funds_at_risk": funds,
                    "poc": poc,
                    "impact": impact,
                    "likelihood": likelihood,
                    "matrix_score": matrix_score,
                }
            )
        return results

    def generate(self, findings: List[Finding], poc: Optional[str] = None) -> str:
        template = self._env.get_template("immunefi.md.j2")
        context = {
            "platform": self.platform_name,
            "findings": self._normalize(findings),
            "global_poc": poc,
        }
        return template.render(**context)

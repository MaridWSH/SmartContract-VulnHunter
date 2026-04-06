from typing import List, Optional, Dict, Any
from jinja2 import Environment, FileSystemLoader
import os
from .base import BaseReporter

Finding = Any

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


class Code4renaReporter(BaseReporter):
    def __init__(self) -> None:
        self._env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

    @property
    def platform_name(self) -> str:
        return "Code4rena"

    def _normalize(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for idx, f in enumerate(findings, start=1):
            fid = getattr(f, "id", idx)
            title = getattr(f, "title", f"Finding {fid}")
            description = getattr(f, "description", "")
            sev_raw = getattr(f, "severity", "Medium")
            poc = getattr(f, "poc", None)
            impact = getattr(f, "impact", None)
            likelihood = getattr(f, "likelihood", None)
            funds = getattr(f, "funds_at_risk", None)

            # Normalize to Code4rena-friendly severities: High/Medium for main findings, Low for lows
            if isinstance(sev_raw, str):
                sev_upper = sev_raw.capitalize()
            else:
                sev_upper = "Medium"

            if sev_upper not in {"High", "Medium", "Low"}:
                # map unknowns to sensible defaults
                sev_upper = "Medium"

            # Compute a simple matrix score if possible (used for some Code4rena visuals)
            matrix_score = None
            if isinstance(impact, (int, float)) and isinstance(
                likelihood, (int, float)
            ):
                matrix_score = int(impact * likelihood)

            result.append(
                {
                    "id": fid,
                    "title": title,
                    "description": description,
                    "severity": sev_upper,
                    "impact": impact,
                    "likelihood": likelihood,
                    "matrix_score": matrix_score,
                    "funds_at_risk": funds,
                    "poc": poc,
                }
            )
        return result

    def generate(self, findings: List[Finding], poc: Optional[str] = None) -> str:
        template = self._env.get_template("code4rena.md.j2")
        context = {
            "platform": self.platform_name,
            "findings": self._normalize(findings),
            "global_poc": poc,
        }
        return template.render(**context)

from typing import List, Optional, Dict, Any
from jinja2 import Environment, FileSystemLoader
import os
from .base import BaseReporter

Finding = Any

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


class CodehawksReporter(BaseReporter):
    def __init__(self) -> None:
        self._env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

    @property
    def platform_name(self) -> str:
        return "Codehawks"

    def _normalize(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for idx, f in enumerate(findings, start=1):
            fid = getattr(f, "id", idx)
            title = getattr(f, "title", f"Finding {fid}")
            description = getattr(f, "description", "")
            impact = getattr(f, "impact", 1)
            likelihood = getattr(f, "likelihood", 1)
            poc = getattr(f, "poc", None)

            # Compute matrix score: impact × likelihood. Map to standard severity bands.
            if isinstance(impact, (int, float)) and isinstance(
                likelihood, (int, float)
            ):
                matrix_score = int(impact * likelihood)
            else:
                matrix_score = None

            # Severity from matrix score: 10+ Critical, 7-9 High, 4-6 Medium, <=3 Low
            if matrix_score is None:
                severity = "Low"
            elif matrix_score >= 10:
                severity = "Critical"
            elif matrix_score >= 7:
                severity = "High"
            elif matrix_score >= 4:
                severity = "Medium"
            else:
                severity = "Low"

            normalized.append(
                {
                    "id": fid,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "impact": impact,
                    "likelihood": likelihood,
                    "matrix_score": matrix_score,
                    "poc": poc,
                }
            )
        return normalized

    def generate(self, findings: List[Finding], poc: Optional[str] = None) -> str:
        template = self._env.get_template("codehawks.md.j2")
        context = {
            "platform": self.platform_name,
            "findings": self._normalize(findings),
            "global_poc": poc,
        }
        return template.render(**context)

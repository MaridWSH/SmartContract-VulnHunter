import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional


# Lightweight Finding model used by the PoC generator.
# This is a minimal representation suitable for PoC generation.
@dataclass
class Finding:
    id: str
    title: str
    vulnerability_type: str
    description: str
    severity: str
    contract_name: Optional[str] = None


class PoCGenerator:
    """Foundry PoC auto-generation utility.

    Responsibilities:
    - Generate Foundry test files for a given finding and contract code
    - Generate exploit skeletons using language templates
    """

    TEMPLATE_DIR = Path(__file__).parent / "templates"

    TEMPLATE_MAP = {
        "reentrancy": "reentrancy.t.sol.j2",
        "flash loan": "flash_loan.t.sol.j2",
        "oracle manipulation": "oracle_manipulation.t.sol.j2",
        "access control": "access_control.t.sol.j2",
    }

    def _extract_contract_name(self, contract_code: str) -> str:
        # Attempt to derive the contract name from the provided source code
        match = re.search(r"contract\s+([A-Za-z0-9_]+)", contract_code)
        if match:
            return match.group(1)
        # Fallback to generic name if extraction fails
        return "TargetContract"

    def _render_template(self, template_path: Path, context: Dict[str, str]) -> str:
        try:
            # Prefer a lightweight Jinja2 rendering if available
            from jinja2 import Environment, FileSystemLoader

            env = Environment(loader=FileSystemLoader(template_path.parent))
            template = env.get_template(template_path.name)
            return template.render(**context)
        except Exception:
            # Fallback: naive string substitution for compatibility
            with template_path.open("r", encoding="utf-8") as fh:
                content = fh.read()
            for k, v in context.items():
                content = content.replace("{{ " + k + " }}", str(v))
            return content

    def generate_test(self, finding: Finding, contract_code: str) -> str:
        """Generate a Foundry test file for the given finding.

        The function returns the test file content as a string. The caller is
        responsible for persisting the content to disk.
        """
        contract_name = finding.contract_name or self._extract_contract_name(
            contract_code
        )

        template_name = self.TEMPLATE_MAP.get(
            finding.vulnerability_type.lower(), "access_control.t.sol.j2"
        )
        template_path = self.TEMPLATE_DIR / template_name

        context = {
            "contract_name": contract_name,
            "test_name": f"poc_{finding.id}_{finding.vulnerability_type}",
            "finding_id": finding.id,
            "vulnerability_type": finding.vulnerability_type,
            "description": finding.description,
            "severity": finding.severity,
        }

        test_content = self._render_template(template_path, context)
        return test_content

    def generate_exploit(self, vulnerability_type: str, params: Dict[str, str]) -> str:
        """Generate a standalone exploit skeleton for a given vulnerability type.

        Uses the appropriate template, populated with supplied parameters.
        """
        tmpl = self.TEMPLATE_MAP.get(vulnerability_type.lower())
        if not tmpl:
            tmpl = self.TEMPLATE_MAP["reentrancy"]  # default to a sane template
        template_path = self.TEMPLATE_DIR / tmpl
        # Provide a permissive context that the templates can reference
        context = {**params}
        return self._render_template(template_path, context)

from __future__ import annotations

import asyncio
import json
import shutil
from typing import List

from .base import ToolAdapter
from vulnhunter.findings import Finding


class CargoAuditAdapter(ToolAdapter):
    """Adapter for Rust Cargo Audit tool.

    - name: cargo-audit
    - Command (example): cargo audit --json
    - Output: JSON with vulnerabilities found in dependencies.
    - Maps to Finding model for each advisory
    """

    name = "cargo-audit"

    def is_available(self) -> bool:
        # cargo-audit is usually installed as a separate binary named cargo-audit
        return shutil.which("cargo-audit") is not None

    async def _run_json(self) -> (str, str, int):
        proc = await asyncio.create_subprocess_exec(
            "cargo",
            "audit",
            "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return (
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
            proc.returncode,
        )

    async def run(self, target: str) -> List[Finding]:
        """Run cargo audit on the workspace at target and parse results."""
        findings: List[Finding] = []

        if not self.is_available():
            findings.append(
                Finding(
                    title="cargo-audit unavailable",
                    description="cargo-audit executable not found in PATH",
                    severity="Low",
                    location=target,
                    source=self.name,
                    raw=None,
                )
            )
            return findings

        stdout, stderr, code = await self._run_json()
        if code != 0:
            # Non-zero exit may still contain useful JSON; try to parse stdout first
            pass

        data = None
        try:
            data = json.loads(stdout) if stdout else {}
        except json.JSONDecodeError:
            data = {"raw_output": stdout}

        # Try multiple known structures
        vulnerabilities = []
        if isinstance(data, dict):
            # cargo-audit v0.12+ often uses data["vulnerabilities"]["list"]
            vuln_container = data.get("vulnerabilities") or {}
            vulnerabilities = (
                vuln_container.get("list") if isinstance(vuln_container, dict) else []
            )

        if not vulnerabilities and isinstance(data, dict):
            # older formats may store advisories under top-level keys
            for key in ("advisories", "issues"):
                val = data.get(key)
                if isinstance(val, dict):
                    # maybe a mapping of advisory_id -> details
                    for adv in val.values():
                        if isinstance(adv, dict):
                            vulnerabilities.append(adv)

        # Normalize findings
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            pkg = item.get("package_name") or item.get("package")
            ver = item.get("affected_version") or item.get("package_version")
            title = (
                item.get("title") or item.get("summary") or (f"Vulnerability in {pkg}")
            )
            description = (
                item.get("description") or item.get("details") or "No description"
            )
            sev = item.get("severity") or item.get("cvssV3", {}).get("score")
            loc = f"{pkg}@{ver}" if pkg else target
            findings.append(
                Finding(
                    title=f"Cargo Audit: {title}",
                    description=description,
                    severity=str(sev) if sev is not None else "Info",
                    location=loc,
                    source=self.name,
                    raw=item,
                )
            )

        if not findings:
            findings.append(
                Finding(
                    title="cargo-audit: no vulnerable dependencies detected",
                    description=stderr or stdout if "stdout" in locals() else "",
                    severity="Info",
                    location=target,
                    source=self.name,
                    raw=data,
                )
            )
        return findings

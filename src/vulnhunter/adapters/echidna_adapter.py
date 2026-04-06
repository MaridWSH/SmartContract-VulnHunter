import asyncio
import json
import shutil
from typing import List, Optional

# Fallback Finding class if the project's shared model isn't available in this environment
try:
    from vulnhunter.findings import Finding
except Exception:
    from dataclasses import dataclass

    @dataclass
    class Finding:
        title: str
        severity: str
        description: str = ""
        evidence: str = ""
        location: Optional[str] = None


from .base import ToolAdapter  # type: ignore


class EchidnaAdapter(ToolAdapter):
    name = "echidna"
    timeout_seconds = 600  # long timeout as required

    def __init__(self):
        super().__init__()

    def is_available(self) -> bool:
        return shutil.which("echidna") is not None

    async def run(self, target: str) -> List[Finding]:
        # Run Echidna in the target directory
        cmd = ["echidna", ".", "--format", "json", "--test-mode", "assertion"]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.communicate()
            except Exception:
                pass
            return [
                Finding(
                    title="Echidna fuzzing timed out",
                    severity="Medium",
                    description=f"Echidna run did not finish within {self.timeout_seconds} seconds.",
                )
            ]
        out_text = (stdout or b"").decode("utf-8", errors="replace")
        err_text = (stderr or b"").decode("utf-8", errors="replace")

        findings: List[Finding] = []

        # Best-effort JSON parse
        data = None
        if out_text:
            try:
                data = json.loads(out_text)
            except Exception:
                data = None

        def add_from_item(item: dict):
            nonlocal findings
            prop = item.get("property") or item.get("name") or item.get("test") or "unknown"
            status = item.get("status")
            passed = item.get("passed")
            failed = (status is not None and str(status).lower() in {"failed", "false"}) or (
                passed is False
            )
            if failed:
                title = f"Echidna: property {prop} failed"
                description = (
                    item.get("description")
                    or item.get("reason")
                    or "Echidna reported a failing property"
                )
                findings.append(
                    Finding(
                        title=title,
                        severity="High",
                        description=description,
                        evidence=json.dumps(item),
                    )
                )

        if isinstance(data, list):
            for it in data:
                if isinstance(it, dict):
                    add_from_item(it)
        elif isinstance(data, dict):
            for key in ("results", "properties", "films", "failures", "tests"):
                if isinstance(data.get(key), list):
                    for it in data.get(key, []):
                        if isinstance(it, dict):
                            add_from_item(it)
                    break

        # Fallback: parse stderr/text for failing signals
        if not findings:
            for line in (out_text + "\n" + err_text).splitlines():
                if line.strip() and (
                    line.lower().find("failed") != -1 or line.lower().find("assert") != -1
                ):
                    findings.append(
                        Finding(
                            title="Echidna fuzzing reported failure",
                            severity="High",
                            description=line,
                            evidence=line,
                        )
                    )

        return findings

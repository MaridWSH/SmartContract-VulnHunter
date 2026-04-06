import asyncio
import json
import shutil
from typing import List, Optional

# Fallback Finding class if not available
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


class FoundryAdapter(ToolAdapter):
    name = "foundry"
    timeout_seconds = 900

    def __init__(self):
        super().__init__()

    def is_available(self) -> bool:
        return shutil.which("forge") is not None or shutil.which("foundry") is not None

    async def run(self, target: str) -> List[Finding]:
        # Use forge if available; some setups expose 'forge' binary
        cmd = ["forge", "test", "--fuzz-runs", "1000", "--json"]
        if shutil.which("forge") is None:
            # Try a Foundry alias if present
            cmd = ["foundry", "test", "--fuzz-runs", "1000", "--json"]

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
                    title="Foundry fuzzing timed out",
                    severity="Medium",
                    description=f"Timeout after {self.timeout_seconds}s",
                )
            ]

        out_text = (stdout or b"").decode("utf-8", errors="replace")
        err_text = (stderr or b"").decode("utf-8", errors="replace")

        findings: List[Finding] = []

        # Attempt to parse JSON output
        data = None
        if out_text:
            try:
                data = json.loads(out_text)
            except json.JSONDecodeError:
                data = None

        def add_finding_from_test(test: dict):
            nonlocal findings
            name = test.get("name") or test.get("test") or "unknown_test"
            status = test.get("status")
            ok = test.get("ok") or test.get("success")
            failed = (
                status is not None and str(status).lower() in {"fail", "failed"}
            ) or (isinstance(ok, bool) and not ok)
            if failed:
                title = f"Foundry test failed: {name}"
                description = (
                    test.get("stdout")
                    or test.get("summary")
                    or "Test failed during fuzz testing"
                )
                findings.append(
                    Finding(
                        title=title,
                        severity="High",
                        description=description,
                        evidence=json.dumps(test),
                    )
                )

        if isinstance(data, list):
            for t in data:
                if isinstance(t, dict):
                    add_finding_from_test(t)
        elif isinstance(data, dict):
            # common shape: {"tests": [...]}
            tests = data.get("tests") or data.get("results") or []
            if isinstance(tests, list):
                for t in tests:
                    if isinstance(t, dict):
                        add_finding_from_test(t)
        # Inline invariant testing hints (if present)
        if not findings and err_text:
            for line in err_text.splitlines():
                if line.strip() and (
                    "invariant" in line.lower() or "assert" in line.lower()
                ):
                    findings.append(
                        Finding(
                            title="Foundry invariant test issue",
                            severity="High",
                            description=line,
                            evidence=line,
                        )
                    )

        return findings

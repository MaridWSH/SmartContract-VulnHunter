"""
Sec3 X-ray Adapter for Solana static analysis (SVEs)

This adapter shells out to the Sec3 X-ray tool (or its legacy name xray)
to perform static analysis on a Solana target and parses the resulting
JSON output into Finding-like objects.
"""

from typing import Any, List, Optional
import asyncio
import json
from shutil import which

from .base import ToolAdapter


class Sec3XrayAdapter(ToolAdapter):
    """Adapter for the Sec3 X-ray static analysis tool."""

    name = "sec3-xray"

    @classmethod
    def is_available(cls) -> bool:
        """Return True if either 'xray' or 'sec3-xray' command is present."""
        return which("xray") is not None or which("sec3-xray") is not None

    async def run(self, target: str) -> List[Any]:
        """Run the static analysis on the given target and return a list of Finding-like objects.

        It tries:
          - xray analyze <target> --format json
          - sec3-xray analyze <target> --format json
        The command is executed with a 120-second timeout.
        """
        # Prepare candidate commands in order of preference
        candidates = [
            ["xray", "analyze", target, "--format", "json"],
            ["sec3-xray", "analyze", target, "--format", "json"],
        ]

        last_error: Optional[Exception] = None
        for cmd in candidates:
            try:
                stdout = await self._run_command(cmd, timeout_seconds=120)
                findings = self._parse_output(stdout)
                if findings is not None:
                    return findings
            except FileNotFoundError:
                # Tool not installed yet; try next candidate
                last_error = FileNotFoundError(f"Command not found: {cmd[0]}")
                continue
            except asyncio.TimeoutError:
                last_error = asyncio.TimeoutError(
                    "sec3-xray timed out after 120 seconds"
                )
                continue
            except Exception as exc:
                last_error = exc
                # Try next candidate in case of a partial failure
                continue

        # If we reach here, all attempts failed gracefully.
        if last_error is not None:
            # Do not raise to keep the caller resilient; return empty list.
            return []
        return []

    async def _run_command(self, cmd: List[str], timeout_seconds: int) -> str:
        """Execute a command asynchronously and return stdout as string.

        Raises FileNotFoundError if the executable is missing, asyncio.TimeoutError on timeout,
        or RuntimeError if the command exits with non-zero status.
        """
        # Use asyncio to avoid blocking the event loop
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise asyncio.TimeoutError("Command timed out")

        if process.returncode != 0:
            # If the process failed, still try to return stdout if any, but raise to indicate failure
            error_text = (stderr or b"").decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"Command {' '.join(cmd)} failed with exit code {process.returncode}: {error_text}"
            )

        # Decode stdout to string
        return (stdout or b"").decode("utf-8", errors="replace")

    def _parse_output(self, text: str) -> List[Any]:
        """Parse the JSON output produced by Sec3 X-ray / xray and map to Finding-like objects."""
        if not text:
            return []

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []

        vulnerabilities = data.get("vulnerabilities") or []
        results: List[Any] = []

        for vuln in vulnerabilities:
            finding = type("Finding", (), {})()  # lightweight container for results
            # Basic fields
            finding.title = vuln.get("name") or vuln.get("title")
            sev = vuln.get("severity")
            finding.severity = self._normalize_severity(sev)
            finding.description = vuln.get("description")

            # Location information
            loc = vuln.get("location") or {}
            finding.location = type("Location", (), {})()
            finding.location.file = loc.get("file")
            line = loc.get("line") or loc.get("start_line")
            finding.location.start_line = (
                int(line)
                if isinstance(line, (int, float, str)) and str(line).isdigit()
                else None
            )

            # Metadata: SVE identifier
            finding.metadata = {"sve_id": vuln.get("sve_id")}

            results.append(finding)

        return results

    @staticmethod
    def _normalize_severity(sev: Any) -> str:
        if isinstance(sev, str):
            s = sev.strip().lower()
            if s in {"critical", "crit"}:
                return "Critical"
            if s in {"high", "h"}:
                return "High"
            if s in {"medium", "med", "m"}:
                return "Medium"
            if s in {"low", "l"}:
                return "Low"
            return sev.capitalize()
        # If numeric or unknown, map to a reasonable default
        if isinstance(sev, int):
            if sev >= 4:
                return "Critical"
            if sev == 3:
                return "High"
            if sev == 2:
                return "Medium"
            return "Low"
        return "Medium"

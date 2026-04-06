"""Caracal adapter for Cairo/StarkNet analysis.

This adapter integrates the Caracal Cairo analyzer into the vulnhunter
framework. It runs asynchronously, parses Caracal's output (preferring JSON
when available), and maps findings into the generic Finding model used by the
rest of the system.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import List, Optional, Any
from shutil import which

try:
    # Preferred import path if the project exposes a common ToolAdapter base
    from src.vulnhunter.adapters.base import ToolAdapter
except Exception:
    try:
        from vulnhunter.adapters.base import ToolAdapter
    except Exception:
        # Minimal fallback so the adapter can be defined in isolation
        class ToolAdapter:  # type: ignore
            name: str = "base"

            @staticmethod
            def is_available() -> bool:
                return False

            async def run(self, target: str) -> List[Any]:  # pragma: no cover
                return []


logger = logging.getLogger(__name__)


class CaracalAdapter(ToolAdapter):
    name = "caracal"

    @staticmethod
    def is_available() -> bool:
        """Return True if the caracal executable is found on PATH."""
        return which("caracal") is not None

    async def run(self, target: str) -> List[Any]:
        """Run Caracal on the given target and return a list of Finding objects.

        The target is typically a Cairo file path or a directory with Cairo sources.
        We prefer JSON output via --format json, but gracefully fall back to text
        if necessary and parse accordingly.
        """
        if not self.is_available():
            raise FileNotFoundError("caracal not found on PATH")

        # Try JSON output first for robust parsing, then fall back to plain text
        cmd_variants = [
            ["caracal", "detect", target, "--format", "json"],
            ["caracal", "detect", target],
        ]

        stdout = ""
        stderr = ""
        last_error: str = ""
        proc: Optional[asyncio.subprocess.Process] = None
        for cmd in cmd_variants:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, err = await proc.communicate()
                stdout = (out or b"").decode("utf-8", errors="ignore").strip()
                stderr = (err or b"").decode("utf-8", errors="ignore").strip()
                if proc.returncode == 0:
                    break
                last_error = stderr or stdout
            except FileNotFoundError:
                # caracal disappeared, re-raise to caller
                raise
            except Exception as exc:  # pragma: no cover
                last_error = str(exc)

        if proc is None or proc.returncode != 0:
            error_msg = last_error or stderr or "caracal failed to run"
            logger.error("caracal failed: %s", error_msg)
            raise RuntimeError(
                f"caracal failed to run on target '{target}': {error_msg}"
            )

        items: List[Any] = []
        # Attempt JSON parsing first
        try:
            data = json.loads(stdout)
            if isinstance(data, dict):
                if "issues" in data:
                    items = data["issues"]
                elif "findings" in data:
                    items = data["findings"]
                else:
                    items = [data]
            elif isinstance(data, list):
                items = data
        except Exception:
            # Fallback: parse line-based textual output
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                # Expected pattern: <severity> - <description> at <file>:<line>
                m = re.match(
                    r"(?i)(?P<sev>critical|high|medium|low|info)?\s*[:-]?\s*(?P<desc>.*?)(?:\s+at\s+(?P<file>[^:]+):(?P<line>\d+))?$",
                    line,
                )
                if not m:
                    # loose match: just a message
                    items.append({"severity": "info", "description": line})
                else:
                    sev = (m.group("sev") or "info").lower()
                    desc = m.group("desc").strip() if m.group("desc") else line
                    items.append(
                        {
                            "severity": sev,
                            "description": desc,
                            "file": m.group("file"),
                            "line": int(m.group("line")) if m.group("line") else None,
                        }
                    )

        # Resolve Finding class dynamically or fallback
        Finding = None
        for mod_path in [
            "src.vulnhunter.finding",
            "vulnhunter.finding",
            "src.vulnhunter.findings",
            "vulnhunter.findings",
        ]:
            try:
                mod = __import__(mod_path, fromlist=["Finding"])
                Finding = getattr(mod, "Finding")
                break
            except Exception:
                continue
        if Finding is None:

            class Finding:  # lightweight fallback
                def __init__(
                    self,
                    description: str,
                    severity: str,
                    file_path: Optional[str] = None,
                    line: Optional[int] = None,
                    tool: Optional[str] = None,
                ):
                    self.description = description
                    self.severity = severity
                    self.file_path = file_path
                    self.line = line
                    self.tool = tool or self.__class__.__name__.lower()

                def __repr__(self):  # type: ignore
                    return (
                        f"Finding(severity={self.severity}, file={self.file_path}, line={self.line}, "
                        f"desc={self.description})"
                    )

        findings: List[Finding] = []  # type: ignore
        for it in items:
            if isinstance(it, Finding):
                findings.append(it)
                continue
            if isinstance(it, dict):
                severity_raw = str(
                    it.get("severity") or it.get("level") or "info"
                ).lower()
                sev_map = {
                    "critical": "Critical",
                    "high": "High",
                    "medium": "Medium",
                    "low": "Low",
                    "info": "Informational",
                }
                severity = sev_map.get(severity_raw, "Informational")
                description = (
                    it.get("description")
                    or it.get("message")
                    or it.get("desc")
                    or str(it)
                )
                file_path = it.get("file") or it.get("path")
                line = it.get("line")
            else:
                description = str(it)
                severity = "Informational"
                file_path = None
                line = None
            findings.append(
                Finding(
                    description=description,
                    severity=severity,
                    file_path=file_path,
                    line=line,
                    tool=self.name,
                )
            )

        return findings

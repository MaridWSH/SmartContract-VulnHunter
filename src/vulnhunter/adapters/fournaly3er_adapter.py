import asyncio
import json
import os
import shutil
from typing import List

from vulnhunter.adapters.base import ToolAdapter
from vulnhunter.models import Finding


class Fournaly3erAdapter(ToolAdapter):
    # Adapter name as required
    name = "4naly3er"

    @classmethod
    def is_available(cls) -> bool:
        # Primary check: is the 4naly3er CLI available
        if shutil.which("4naly3er") is not None:
            return True

        # Fallback: check for a local package.json with an analyze script
        pkg_path = os.path.join(os.getcwd(), "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                scripts = data.get("scripts", {})
                if isinstance(scripts, dict) and "analyze" in scripts:
                    return True
            except Exception:
                # Any parsing error means we can't confirm availability here
                return False

        # If neither, 4naly3er is not available in this environment
        return False

    async def run(self, target: str) -> List[Finding]:
        """Run 4naly3er analysis on the given target and return findings.

        Preference order for invocation:
        - yarn analyze <target> if a package.json with analyze script exists
        - npm run analyze -- <target> if yarn is not available but npm exists
        - fall back to 4naly3er analyze <target> if the CLI is installed
        """
        # Determine invocation command
        cmd = None

        # Prefer explicit 4naly3er CLI if available
        if shutil.which("4naly3er") is not None:
            cmd = ["4naly3er", "analyze", target]
        else:
            # Check package.json for an analyze script
            pkg_scripts = {}
            if os.path.exists(os.path.join(os.getcwd(), "package.json")):
                try:
                    with open(
                        os.path.join(os.getcwd(), "package.json"), "r", encoding="utf-8"
                    ) as f:
                        pkg_scripts = json.load(f).get("scripts", {}) or {}
                except Exception:
                    pkg_scripts = {}

            has_analyze_script = (
                isinstance(pkg_scripts, dict) and "analyze" in pkg_scripts
            )

            if has_analyze_script:
                if shutil.which("yarn"):
                    cmd = ["yarn", "analyze", target]
                elif shutil.which("npm"):
                    cmd = ["npm", "run", "analyze", "--", target]
            # Last resort: try a direct 4naly3er invocation if the CLI is not on PATH
            if cmd is None and shutil.which("4naly3er") is None:
                # Best effort: attempt to call via npx if available
                if shutil.which("npx"):
                    cmd = ["npx", "4naly3er", "analyze", target]

        if cmd is None:
            # Unable to determine how to run the analyzer
            return []

        # Execute the command asynchronously and capture output
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
        except FileNotFoundError:
            # Command not found; graceful fallback
            return []

        # If non-zero exit, treat as a non-fatal error for now and return empty
        if proc.returncode != 0:
            # Normalize error string for logging/debugging
            err_text = (stderr or b"").decode("utf-8", errors="ignore").strip()
            # Do not raise to keep the pipeline resilient
            return []

        raw_output = (
            stdout.decode("utf-8", errors="ignore")
            if isinstance(stdout, (bytes, bytearray))
            else stdout
        )

        findings: List[Finding] = []

        # Try JSON first
        try:
            data = json.loads(raw_output)
            items = []
            if isinstance(data, dict):
                items = data.get("findings") or data.get("issues") or []
            elif isinstance(data, list):
                items = data
            for it in items:
                sev = str(it.get("severity") or it.get("level") or "Info")
                line = it.get("line") or it.get("lineno")
                file_path = it.get("file") or it.get("filename")
                desc = it.get("description") or it.get("message") or ""
                findings.append(
                    Finding(description=desc, severity=sev, line=line, file=file_path)
                )
            if findings:
                return findings
        except Exception:
            # Fall through to Markdown parsing if JSON failed
            pass

        # Fallback: parse Markdown-like output
        md = raw_output
        import re

        for line in md.splitlines():
            s = line.strip()
            if s.startswith("- ") or s.startswith("* "):
                content = s[2:].strip()
                sev = "Info"
                m = re.search(r"\(Severity:\s*([A-Za-z]+)\s*\)", content)
                if m:
                    sev = m.group(1)
                m_file = re.search(r"([^\s:]+\.[a-zA-Z0-9]+):(\d+)", content)
                file_path = m_file.group(1) if m_file else None
                line_no = int(m_file.group(2)) if m_file else None
                desc = content
                if "(Severity:" in content:
                    desc = content.split("(Severity:")[0].strip()
                findings.append(
                    Finding(
                        description=desc, severity=sev, line=line_no, file=file_path
                    )
                )

        return findings

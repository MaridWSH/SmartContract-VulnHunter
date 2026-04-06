import asyncio
import json
import os
import shutil
import uuid
from typing import List

# Lightweight fallback models in case the main project imports fail during tests
try:
    from vulnhunter.findings import Finding, Location  # type: ignore
except Exception:
    from dataclasses import dataclass

    @dataclass
    class Location:
        file: str
        start_line: int

    @dataclass
    class Finding:
        title: str
        severity: str
        description: str
        location: Location


# Minimal fallback for base adapter if the project layout differs in tests
try:
    from vulnhunter.adapters.base import ToolAdapter  # type: ignore
except Exception:

    class ToolAdapter:  # type: ignore
        pass


class AderynAdapter(ToolAdapter):
    name = "aderyn"

    @staticmethod
    def is_available() -> bool:
        # Detect if the aderyn CLI is installed and on PATH
        return shutil.which("aderyn") is not None

    async def run(self, target: str) -> List[Finding]:
        """Run aderyn against the given target and return a list of Findings.

        Output is parsed from JSON first; if SARIF is available, it can be parsed as a
        fallback/alternative. All temp files are cleaned up after processing.
        """

        # Short-circuit if not available
        if not self.is_available():
            return []

        findings: List[Finding] = []
        tmp_json = f"/tmp/aderyn_{uuid.uuid4()}.json"
        tmp_sarif = f"/tmp/aderyn_{uuid.uuid4()}.sarif"

        # Helper for severity normalization
        def _norm_severity(sev: str) -> str:
            if not isinstance(sev, str):
                return "Medium"
            s = sev.strip().lower()
            if s in {"high", "critical"}:
                return "High"
            if s in {"medium", "med"}:
                return "Medium"
            if s in {"low", "informational", "note"}:
                return "Low"
            return "Medium"

        # Build the json workflow
        json_cmd = ["aderyn", target, "-o", "json", "--output-path", tmp_json]
        sarif_cmd = ["aderyn", target, "-o", "sarif", "--output-path", tmp_sarif]

        # Run JSON output first
        try:
            proc = await asyncio.create_subprocess_exec(
                *json_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return findings

            if proc.returncode == 0 and os.path.exists(tmp_json):
                try:
                    with open(tmp_json, "r", encoding="utf-8") as f:
                        payload = json.load(f)
                    issues = []
                    if isinstance(payload, dict):
                        # Common patterns
                        if "issues" in payload and isinstance(payload["issues"], list):
                            issues = payload["issues"]
                        elif "findings" in payload and isinstance(
                            payload["findings"], list
                        ):
                            issues = payload["findings"]
                    if not issues:
                        issues = []  # fallback

                    for issue in issues:
                        if not isinstance(issue, dict):
                            continue
                        title = (
                            issue.get("title") or issue.get("name") or "Vulnerability"
                        )
                        severity = _norm_severity(
                            issue.get("severity") or issue.get("level") or "Medium"
                        )
                        description = (
                            issue.get("description")
                            or issue.get("description_text")
                            or ""
                        )
                        line_no = issue.get("line_no") or issue.get("start_line") or 0
                        file_path = (
                            issue.get("file_path")
                            or issue.get("file")
                            or issue.get("location", {}).get("file", "")
                        )
                        loc = Location(
                            file=file_path, start_line=int(line_no) if line_no else 0
                        )
                        findings.append(
                            Finding(
                                title=title,
                                severity=severity,
                                description=description,
                                location=loc,
                            )
                        )
                except Exception:
                    # JSON parse or processing fail gracefully; try SARIF fallback below
                    pass
            # If we got no findings yet, try SARIF as a fallback
            if not findings and os.path.exists(tmp_sarif):
                try:
                    proc2 = await asyncio.create_subprocess_exec(
                        *sarif_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(
                            proc2.communicate(), timeout=60
                        )
                    except asyncio.TimeoutError:
                        proc2.kill()
                        await proc2.wait()
                        return findings
                    if proc2.returncode == 0:
                        with open(tmp_sarif, "r", encoding="utf-8") as f:
                            sarif = json.load(f)
                        runs = sarif.get("runs", [])
                        if isinstance(runs, list) and runs:
                            for res in runs[0].get("results", []):
                                title = res.get("name") or res.get("message", {}).get(
                                    "text", "Vulnerability"
                                )
                                # severity mapping
                                sev_raw = res.get("level", "Medium")
                                severity = _norm_severity(sev_raw)
                                description = res.get("message", {}).get("text", "")
                                # location
                                locs = res.get("locations", [])
                                file_path = ""
                                line_no = 0
                                if isinstance(locs, list) and len(locs) > 0:
                                    pl = locs[0].get("physicalLocation", {})
                                    file_path = pl.get("artifactLocation", {}).get(
                                        "uri", ""
                                    )
                                    region = pl.get("region", {})
                                    line_no = region.get("startLine", 0)
                                loc = Location(
                                    file=file_path,
                                    start_line=int(line_no) if line_no else 0,
                                )
                                findings.append(
                                    Finding(
                                        title=title,
                                        severity=severity,
                                        description=description,
                                        location=loc,
                                    )
                                )
                except Exception:
                    pass

        except FileNotFoundError:
            # aderyn not found or output path invalid; return empty findings gracefully
            return []
        except Exception:
            return []
        finally:
            # Cleanup temp files
            try:
                if os.path.exists(tmp_json):
                    os.remove(tmp_json)
            except Exception:
                pass
            try:
                if os.path.exists(tmp_sarif):
                    os.remove(tmp_sarif)
            except Exception:
                pass

        return findings

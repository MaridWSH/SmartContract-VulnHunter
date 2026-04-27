"""Contest pipeline for onboarding, analysis, and draft generation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from vulnhunter.contest.adapter import ContestAdapter, ContestMetadata

logger = logging.getLogger(__name__)


class ContestPipeline:
    """Pipeline for contest participation."""

    def __init__(self, adapter: ContestAdapter):
        self.adapter = adapter
        self.metadata: Optional[ContestMetadata] = None

    def onboard(self, contest_url: str, output_dir: Optional[Path] = None) -> Path:
        """Onboard a contest: fetch metadata, clone repo, write config."""
        logger.info(f"Onboarding contest: {contest_url}")

        self.metadata = self.adapter.onboard(contest_url)

        output_dir = output_dir or Path(".vulnhunter-contest")
        output_dir.mkdir(parents=True, exist_ok=True)

        config_path = output_dir / ".vulnhunter-contest.toml"
        config = {
            "id": self.metadata.id,
            "name": self.metadata.name,
            "platform": self.metadata.platform,
            "repo_url": self.metadata.repo_url,
            "scope_files": self.metadata.scope_files,
            "severity_criteria": self.metadata.severity_criteria,
            "onboarded_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        }

        import tomllib
        import tomli_w
        with open(config_path, "wb") as f:
            tomli_w.dump(config, f)

        logger.info(f"Contest config written to {config_path}")
        return config_path

    def analyze(self, repo_path: Path) -> List[Dict]:
        """Run VulnHunter analysis on in-scope contracts."""
        if not self.metadata:
            config_path = repo_path / ".vulnhunter-contest.toml"
            if not config_path.exists():
                raise ValueError("Contest not onboarded. Run 'onboard' first.")

            import tomllib
            with open(config_path, "rb") as f:
                config = tomllib.load(f)
                self.metadata = ContestMetadata(
                    id=config["id"],
                    name=config["name"],
                    platform=config["platform"],
                    repo_url=config["repo_url"],
                    scope_files=config.get("scope_files", []),
                    severity_criteria=config.get("severity_criteria", {}),
                )

        scope_files = self.adapter.parse_scope(repo_path)
        if not scope_files:
            scope_files = list(repo_path.rglob("*.sol"))
            scope_files = [str(f.relative_to(repo_path)) for f in scope_files]

        logger.info(f"Analyzing {len(scope_files)} files")

        findings = []

        # Run VulnHunter scan on each in-scope file
        for sol_file in scope_files[:20]:  # Limit to 20 files to avoid timeouts
            file_path = repo_path / sol_file
            if not file_path.exists():
                continue

            try:
                # Run the scan command
                from vulnhunter.commands.scan import run_scan
                result = run_scan(str(file_path), adapters=["slither", "mythril", "smtchecker"])

                if result and hasattr(result, 'findings'):
                    for finding in result.findings:
                        findings.append({
                            "title": finding.title,
                            "description": finding.description,
                            "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                            "location": str(finding.location) if finding.location else sol_file,
                            "tool": finding.tool,
                        })
            except Exception as exc:
                logger.warning(f"Failed to analyze {sol_file}: {exc}")
                continue

        # Also run LLM analysis if code is small enough
        total_lines = 0
        for sol_file in scope_files[:5]:
            file_path = repo_path / sol_file
            if file_path.exists():
                total_lines += len(file_path.read_text().splitlines())

        if total_lines < 5000:  # Only run LLM on small codebases
            try:
                from vulnhunter.llm.pipeline import AnalysisPipeline
                from vulnhunter.llm.client import KimiClient
                from vulnhunter.config import get_config

                config = get_config()
                api_key = getattr(config, 'kimi_api_key', '') or ''
                client = KimiClient(api_key=api_key, model='kimi-k2.5')
                pipeline = AnalysisPipeline(client)

                # Combine all code
                all_code = []
                for sol_file in scope_files[:10]:
                    file_path = repo_path / sol_file
                    if file_path.exists():
                        all_code.append(f"// {sol_file}\n{file_path.read_text()}")

                combined_code = '\n\n'.join(all_code)

                import asyncio
                result = asyncio.run(pipeline.analyze_findings(
                    findings=[],
                    code=combined_code,
                    target_path=str(repo_path),
                ))

                if result and hasattr(result, 'verified_findings'):
                    for finding in result.verified_findings:
                        findings.append({
                            "title": finding.title if hasattr(finding, 'title') else str(finding),
                            "description": finding.description if hasattr(finding, 'description') else '',
                            "severity": finding.severity if hasattr(finding, 'severity') else 'medium',
                            "location": finding.location if hasattr(finding, 'location') else 'unknown',
                            "tool": 'vulnhunter-llm',
                        })
            except Exception as exc:
                logger.warning(f"LLM analysis failed: {exc}")

        logger.info(f"Analysis complete: {len(findings)} findings")
        return findings

    def generate_drafts(
        self, findings: List[Dict], output_dir: Path
    ) -> List[Path]:
        """Generate submission drafts for each finding."""
        output_dir = output_dir / "submissions"
        output_dir.mkdir(parents=True, exist_ok=True)

        draft_paths = []
        for i, finding in enumerate(findings, 1):
            draft_text = self.adapter.format_submission(finding, draft=True)
            draft_path = output_dir / f"finding_{i:03d}_{finding.get('severity', 'unknown')}.md"
            draft_path.write_text(draft_text)
            draft_paths.append(draft_path)

        logger.info(f"Generated {len(draft_paths)} submission drafts")
        return draft_paths

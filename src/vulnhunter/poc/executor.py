import asyncio
import json
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class TestResult:
    passed: bool
    output: str
    details: Optional[dict] = None


class PoCExecutor:
    """Executor for running and validating Foundry PoCs.

    - Writes/assumes test files follow Foundry conventions
    - Runs `forge test --json` to obtain structured results
    - Parses JSON output to determine pass/fail
    - Supports forking (fork-url provided via forge environment) in the project
    """

    def __init__(self):
        self._active_fork = None

    async def run_test(
        self,
        test_file: Path,
        project_dir: Path,
        use_tenderly_fork: bool = False,
        tenderly_config: dict | None = None,
    ) -> TestResult:
        # Ensure the test_file path is relative to the project_dir for forge's --match-path
        try:
            rel_path = test_file.resolve().relative_to(project_dir.resolve())
        except Exception:
            rel_path = test_file.name

        cmd = ["forge", "test", "--json", "-vvv", "--match-path", str(rel_path)]

        # Tenderly fork integration
        if use_tenderly_fork and tenderly_config:
            try:
                from vulnhunter.integrations.tenderly import TenderlyClient
                client = TenderlyClient(
                    access_key=tenderly_config["access_key"],
                    account_slug=tenderly_config["account_slug"],
                    project_slug=tenderly_config["project_slug"],
                )
                fork = await client.create_fork(
                    chain_id=tenderly_config.get("chain_id", 1),
                    block_number=tenderly_config.get("block_number"),
                )
                cmd.extend(["--fork-url", fork.rpc_url])
                # Store fork handle for cleanup after test
                self._active_fork = fork
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning(f"Tenderly fork failed: {exc}; running without fork")

        # Optional fork testing support via environment variables
        fork_url = os.environ.get("FORGE_FORK_URL")
        if fork_url and "--fork-url" not in cmd:
            cmd.extend(["--fork-url", fork_url])
            fork_block = os.environ.get("FORGE_FORK_BLOCK")
            if fork_block:
                cmd.extend(["--fork-block-number", fork_block])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(project_dir),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            output = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(
                errors="replace"
            )

            # Try to extract JSON payload from the combined output
            data = None
            text = output
            try:
                data = json.loads(text)
            except Exception:
                # Try to locate a JSON blob within the text
                start = text.find("{")
                end = text.rfind("}")
                if start != -1 and end != -1:
                    try:
                        data = json.loads(text[start : end + 1])
                    except Exception:
                        data = None

            passed = False
            if isinstance(data, dict):
                tests = data.get("tests", [])
                if isinstance(tests, list) and tests:
                    statuses = [t.get("status", "") for t in tests]
                    # A simple heuristic: all tests must have status indicating success
                    passed = all(
                        s.lower() in {"passed", "pass", "ok"} for s in statuses if s
                    )
            # If we couldn't parse a summary, fall back to exit code (0 means pass in many setups)
            if data is None:
                passed = process.returncode == 0

            return TestResult(passed=passed, output=text, details=data)
        finally:
            # Clean up Tenderly fork if created
            if self._active_fork is not None:
                try:
                    await self._active_fork.client.delete_fork(self._active_fork.fork_id)
                except Exception:
                    pass
                self._active_fork = None

    async def validate_poc(self, poc_code: str, target: str) -> bool:
        """Validate a PoC by writing a test file into the target project and running forge test."""
        project_dir = Path(target)
        poc_dir = project_dir / "tests" / "poc_generated"
        poc_dir.mkdir(parents=True, exist_ok=True)
        # Use a stable file name that doesn't clash with existing tests
        test_path = poc_dir / "generated_poc.t.sol"

        # Write the PoC test code
        test_path.write_text(poc_code, encoding="utf-8")

        # Run the test using Forge
        result = await self.run_test(test_path, project_dir)
        return result.passed

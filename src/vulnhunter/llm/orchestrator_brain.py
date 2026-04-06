"""LLM Orchestrator Brain - Kimi K2.5 as the decision maker.

This module implements the core architectural shift where Kimi K2.5:
1. Analyzes recon reports to understand the target
2. Decides which scanners to run, in what order
3. Analyzes scan results and decides if more scanning is needed
4. Generates findings and PoCs

Uses OpenAI-compatible function calling for tool orchestration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Callable

from vulnhunter.config import get_config
from vulnhunter.recon.models import ReconReport
from vulnhunter.knowledge import VulnerabilityKnowledgeBase, Language, load_knowledge_base
from vulnhunter.llm.client import KimiClient


@dataclass
class ToolCall:
    """Represents a tool call requested by the LLM."""

    name: str
    arguments: Dict[str, Any]


@dataclass
class OrchestratorDecision:
    """A decision made by the orchestrator brain."""

    decision_type: str
    reasoning: str
    tool_calls: List[ToolCall]
    context_updates: Dict[str, Any]


class ToolRegistry:
    """Registry of available tools for the orchestrator."""

    def __init__(self):
        self._tools: Dict[str, Dict[str, Any]] = {}
        self._handlers: Dict[str, Callable] = {}

    def register(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable,
    ) -> None:
        """Register a tool."""
        self._tools[name] = {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters,
            },
        }
        self._handlers[name] = handler

    def get_schemas(self) -> List[Dict[str, Any]]:
        """Get tool schemas for LLM function calling."""
        return list(self._tools.values())

    def execute(self, tool_call: ToolCall) -> Any:
        """Execute a tool call."""
        if tool_call.name not in self._handlers:
            raise ValueError(f"Unknown tool: {tool_call.name}")
        return self._handlers[tool_call.name](**tool_call.arguments)


class OrchestratorBrain:
    """Kimi K2.5 as the orchestration brain.

    Analyzes recon reports, decides which scanners to run,
    and orchestrates the entire vulnerability hunting pipeline.
    """

    AVAILABLE_SCANNERS = {
        "solidity": [
            "slither",
            "aderyn",
            "solhint",
            "semgrep",
            "4naly3er",
            "mythril",
            "echidna",
            "medusa",
            "foundry",
            "heimdall",
        ],
        "rust": ["trident", "cargo-audit"],
        "vyper": ["slither-vyper"],
        "cairo": ["caracal"],
    }

    def __init__(self, knowledge_base: Optional[VulnerabilityKnowledgeBase] = None):
        self.config = get_config()
        self.kb = knowledge_base or load_knowledge_base()
        self.tool_registry = self._setup_tools()
        self.conversation_history: List[Dict[str, Any]] = []
        llm_config = self.config.llm
        self.llm_client = KimiClient(
            api_key=llm_config.api_key, base_url=llm_config.base_url or None, model=llm_config.model
        )

    def _setup_tools(self) -> ToolRegistry:
        """Setup the tool registry with available scanners."""
        registry = ToolRegistry()

        # Register scanner tools
        for lang, scanners in self.AVAILABLE_SCANNERS.items():
            for scanner in scanners:
                registry.register(
                    name=f"run_{scanner}",
                    description=f"Run {scanner} scanner on the target",
                    parameters={
                        "type": "object",
                        "properties": {
                            "target_path": {
                                "type": "string",
                                "description": "Path to the target codebase",
                            },
                            "additional_args": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Additional arguments for the scanner",
                            },
                        },
                        "required": ["target_path"],
                    },
                    handler=self._create_scanner_handler(scanner),
                )

        # Register analysis tools
        registry.register(
            name="analyze_findings",
            description="Analyze scanner findings for exploitability",
            parameters={
                "type": "object",
                "properties": {
                    "findings": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "List of findings to analyze",
                    },
                    "context": {
                        "type": "string",
                        "description": "Additional context about the target",
                    },
                },
                "required": ["findings"],
            },
            handler=self._analyze_findings_handler,
        )

        registry.register(
            name="generate_poc",
            description="Generate a PoC exploit for a vulnerability",
            parameters={
                "type": "object",
                "properties": {
                    "vulnerability": {
                        "type": "object",
                        "description": "Vulnerability details",
                    },
                    "target_contract": {
                        "type": "string",
                        "description": "Contract to target",
                    },
                },
                "required": ["vulnerability", "target_contract"],
            },
            handler=self._generate_poc_handler,
        )

        registry.register(
            name="request_more_scanning",
            description="Request additional scanning based on findings",
            parameters={
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Why more scanning is needed",
                    },
                    "suggested_scanners": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of scanners to run",
                    },
                },
                "required": ["reason", "suggested_scanners"],
            },
            handler=self._request_more_scanning_handler,
        )

        return registry

    def _create_scanner_handler(self, scanner: str) -> Callable:
        def get_scanner_cmd(scanner: str, path: str, args: List[str]) -> str:
            # Ensure path is absolute
            if not path.startswith("/"):
                path = f"/tmp/{path}"
            cmds = {
                "slither": f"slither {path} --json - --exclude-dependencies",
                "aderyn": f"aderyn {path} --stdin",
                "semgrep": f"semgrep --config=auto --json {path}",
                "mythril": f"mythril analyze {path} --solver-timeout 60000",
                "echidna": f"echidna {path}",
                "heimdall": f"heimdall analyze {path}",
            }
            base_cmd = cmds.get(scanner, f"{scanner} {path}")
            return f"{base_cmd} {' '.join(args)}" if args else base_cmd

        async def handler(
            target_path: str, additional_args: Optional[List[str]] = None
        ) -> Dict[str, Any]:
            import subprocess
            import asyncio

            args = additional_args or []
            cmd = get_scanner_cmd(scanner, target_path, args)

            try:
                print(f"[EXEC] Running: {cmd}")
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                if process.returncode == 0:
                    return {
                        "scanner": scanner,
                        "target": target_path,
                        "status": "success",
                        "output": stdout.decode()[:50000],
                        "errors": stderr.decode()[:5000] if stderr else "",
                    }
                else:
                    return {
                        "scanner": scanner,
                        "target": target_path,
                        "status": "failed",
                        "returncode": process.returncode,
                        "output": stdout.decode()[:50000],
                        "errors": stderr.decode()[:5000],
                    }
            except Exception as e:
                return {
                    "scanner": scanner,
                    "target": target_path,
                    "status": "error",
                    "message": str(e),
                }

        return handler

    def _analyze_findings_handler(
        self, findings: List[Dict], context: Optional[str] = None
    ) -> Dict[str, Any]:
        """Handle analyze_findings tool call."""
        return {
            "action": "analyze",
            "findings_count": len(findings),
            "context": context,
        }

    def _generate_poc_handler(self, vulnerability: Dict, target_contract: str) -> Dict[str, Any]:
        """Handle generate_poc tool call."""
        return {
            "action": "generate_poc",
            "target": target_contract,
            "vuln_type": vulnerability.get("type", "unknown"),
        }

    def _request_more_scanning_handler(
        self, reason: str, suggested_scanners: List[str]
    ) -> Dict[str, Any]:
        """Handle request_more_scanning tool call."""
        return {
            "action": "more_scanning",
            "reason": reason,
            "scanners": suggested_scanners,
        }

    def create_system_prompt(self, recon_report: ReconReport) -> str:
        """Create the system prompt for the orchestrator."""
        # Get relevant vulnerability knowledge
        languages = [
            Language(lang)
            for lang in recon_report.ecosystems
            if lang in ["solidity", "rust", "vyper", "cairo"]
        ]
        if not languages:
            languages = [Language.SOLIDITY]

        vuln_context = self.kb.get_relevant_for_protocol(
            recon_report.protocol_type or "general",
            languages,
        )

        return f"""You are SmartContract VulnHunter's Orchestration Brain, an expert smart contract security auditor and bug bounty hunter.

Your job is to analyze the target codebase and make intelligent decisions about which security scanners to run.

## Current Target
- Repository: {recon_report.repo_name}
- Ecosystems: {", ".join(recon_report.ecosystems) or "Unknown"}
- Protocol Type: {recon_report.protocol_type or "Unknown"}
- Build Status: {recon_report.build_status}
- Total LOC: {recon_report.total_loc:,}
- External Functions: {recon_report.external_functions}

## Attack Surface Summary
- External Call Sites: {recon_report.external_call_sites}
- Payable Functions: {recon_report.payable_functions}
- Oracle Dependencies: {recon_report.oracle_dependencies}
- Assembly Blocks: {recon_report.assembly_blocks}
- Delegatecall Sites: {recon_report.delegatecall_sites}

## Relevant Vulnerabilities
{vuln_context}

## Your Task
1. Analyze the reconnaissance report above
2. Decide which scanners to run based on:
   - The detected ecosystem (Solidity, Rust, Vyper, Cairo)
   - The protocol type (lending, DEX, vault, etc.)
   - The attack surface indicators
   - Prior audit history and security commits

3. Use the available tools to orchestrate scanning
4. After scanning, analyze findings and decide if more scanning is needed
5. Generate PoCs for confirmed vulnerabilities

## Decision Framework
- High attack surface + DeFi protocol → Run ALL applicable scanners
- Previous audits found → Focus on changes since last audit
- Low test coverage → Prioritize fuzzers (Echidna, Medusa)
- Oracle dependencies → Definitely run Slither, Aderyn
- Cross-chain bridge → Include all signature/cryptography scanners

Make your decisions thoughtfully. You can call multiple tools in sequence.
"""

    async def decide_scan_plan(self, recon_report: ReconReport) -> OrchestratorDecision:
        system_prompt = self.create_system_prompt(recon_report)

        user_prompt = f"""Based on the reconnaissance report for {recon_report.repo_name}, decide which security scanners to run.

Key observations:
- Hot zones: {len(recon_report.hot_zones)} priority targets identified
- Test coverage: {recon_report.test_coverage_percent or "Unknown"}%
- External calls: {recon_report.external_call_sites}
- Oracle deps: {recon_report.oracle_dependencies}
- Assembly blocks: {recon_report.assembly_blocks}

Available scanners: {", ".join(self.AVAILABLE_SCANNERS.get("solidity", []))}

Analyze the attack surface and recommend which scanners to run. Consider:
1. Oracle integration = slither, aderyn (for static analysis)
2. Low test coverage = echidna, medusa (for fuzzing)
3. Assembly usage = heimdall (for bytecode analysis)

Respond with a JSON object containing your scan plan:
{{
  "scanners": ["scanner1", "scanner2", ...],
  "reasoning": "why you chose these scanners"
}}"""

        try:
            tools = self.tool_registry.get_schemas()
            result = await self.llm_client.analyze_with_tools(
                prompt=f"{system_prompt}\n\n{user_prompt}", tools=tools
            )

            print(f"[DEBUG] LLM result: {result}")

            if isinstance(result, dict) and "function" in result:
                func_name = result["function"]
                scanner = func_name.replace("run_", "")
                scanners = [scanner]
                reasoning = f"LLM selected {scanner} based on attack surface analysis"
            elif isinstance(result, dict) and "content" in result:
                import json

                try:
                    content = json.loads(result["content"])
                    scanners = content.get("scanners", [])
                    reasoning = content.get("reasoning", "LLM-based decision")
                except:
                    scanners = []
                    reasoning = result.get("content", "LLM response")
            else:
                scanners = []
                reasoning = "Failed to parse LLM response"

            print(f"[DEBUG] Parsed scanners: {scanners}, reasoning: {reasoning}")

            tool_calls = []
            for scanner in scanners:
                if scanner in self.AVAILABLE_SCANNERS.get("solidity", []):
                    tool_calls.append(
                        ToolCall(
                            name=f"run_{scanner}",
                            arguments={
                                "target_path": str(
                                    recon_report.target_path or recon_report.repo_url
                                )
                            },
                        )
                    )

            if not tool_calls:
                return self._rule_based_decision(recon_report)

            return OrchestratorDecision(
                decision_type="scan_plan",
                reasoning=reasoning,
                tool_calls=tool_calls,
                context_updates={"phase": "scanning", "total_scanners": len(tool_calls)},
            )

        except Exception as e:
            print(f"LLM call failed: {e}, falling back to rule-based")
            return self._rule_based_decision(recon_report)

            return OrchestratorDecision(
                decision_type="scan_plan",
                reasoning=reasoning,
                tool_calls=tool_calls,
                context_updates={"phase": "scanning", "total_scanners": len(tool_calls)},
            )

        except Exception as e:
            print(f"LLM call failed: {e}, falling back to rule-based")
            return self._rule_based_decision(recon_report)

    def _rule_based_decision(self, recon_report: ReconReport) -> OrchestratorDecision:
        """Create a scan plan using rule-based logic (fallback when LLM unavailable)."""
        tool_calls = []
        reasoning_parts = []

        # Determine which ecosystems to scan
        ecosystems = recon_report.ecosystems or ["solidity"]

        for ecosystem in ecosystems:
            if ecosystem not in self.AVAILABLE_SCANNERS:
                continue

            scanners = self.AVAILABLE_SCANNERS[ecosystem]

            # Always run the core static analyzers
            core_scanners = ["slither", "aderyn", "semgrep"]
            for scanner in core_scanners:
                if scanner in scanners:
                    tool_calls.append(
                        ToolCall(
                            name=f"run_{scanner}",
                            arguments={
                                "target_path": str(
                                    recon_report.target_path or recon_report.repo_url
                                )
                            },
                        )
                    )

            reasoning_parts.append(f"{ecosystem}: core static analysis")

            # Run fuzzers if test coverage is low or unknown
            if not recon_report.test_coverage_percent or recon_report.test_coverage_percent < 50:
                fuzzers = ["echidna", "medusa"]
                for fuzzer in fuzzers:
                    if fuzzer in scanners:
                        tool_calls.append(
                            ToolCall(
                                name=f"run_{fuzzer}",
                                arguments={
                                    "target_path": str(
                                        recon_report.target_path or recon_report.repo_url
                                    )
                                },
                            )
                        )
                reasoning_parts.append(f"{ecosystem}: fuzzers (low coverage)")

            # Run Mythril if high attack surface
            if recon_report.external_call_sites > 5 or recon_report.payable_functions > 3:
                if "mythril" in scanners:
                    tool_calls.append(
                        ToolCall(
                            name="run_mythril",
                            arguments={
                                "target_path": str(
                                    recon_report.target_path or recon_report.repo_url
                                )
                            },
                        )
                    )
                reasoning_parts.append(f"{ecosystem}: mythril (high attack surface)")

            # Run Heimdall if assembly blocks found
            if recon_report.assembly_blocks > 0:
                if "heimdall" in scanners:
                    tool_calls.append(
                        ToolCall(
                            name="run_heimdall",
                            arguments={
                                "target_path": str(
                                    recon_report.target_path or recon_report.repo_url
                                )
                            },
                        )
                    )
                reasoning_parts.append(f"{ecosystem}: heimdall (assembly detected)")

        return OrchestratorDecision(
            decision_type="scan_plan",
            reasoning="; ".join(reasoning_parts),
            tool_calls=tool_calls,
            context_updates={"phase": "scanning", "total_scanners": len(tool_calls)},
        )

    def analyze_results(
        self,
        recon_report: ReconReport,
        scan_results: List[Dict[str, Any]],
    ) -> OrchestratorDecision:
        """Analyze scan results and decide next steps."""
        # Count findings by severity
        total_findings = sum(len(r.get("findings", [])) for r in scan_results)
        high_severity = sum(
            1
            for r in scan_results
            for f in r.get("findings", [])
            if f.get("severity") in ["High", "Critical"]
        )

        reasoning = (
            f"Found {total_findings} total findings, {high_severity} high/critical severity."
        )

        tool_calls = []

        # If we found high severity issues, analyze them for exploitability
        if high_severity > 0:
            all_findings = []
            for result in scan_results:
                all_findings.extend(result.get("findings", []))

            high_findings = [f for f in all_findings if f.get("severity") in ["High", "Critical"]]

            tool_calls.append(
                ToolCall(
                    name="analyze_findings",
                    arguments={
                        "findings": high_findings,
                        "context": f"Protocol: {recon_report.protocol_type}, Attack surface: {recon_report.external_call_sites} external calls",
                    },
                )
            )
            reasoning += " Analyzing high-severity findings for exploitability."

        # If external calls found but no reentrancy detected, run more scanners
        if recon_report.external_call_sites > 0 and not any(
            "reentrancy" in str(f) for f in all_findings
        ):
            tool_calls.append(
                ToolCall(
                    name="request_more_scanning",
                    arguments={
                        "reason": f"External calls detected ({recon_report.external_call_sites}) but no reentrancy findings. Need deeper analysis.",
                        "suggested_scanners": ["echidna", "medusa"],
                    },
                )
            )
            reasoning += " Requesting additional fuzzing for reentrancy detection."

        return OrchestratorDecision(
            decision_type="analyze_results",
            reasoning=reasoning,
            tool_calls=tool_calls,
            context_updates={"phase": "analysis", "findings_count": total_findings},
        )

    def should_generate_poc(self, finding: Dict[str, Any]) -> bool:
        """Determine if a finding warrants PoC generation."""
        severity = finding.get("severity", "")
        confidence = finding.get("confidence", "")

        # Generate PoC for high confidence high/critical findings
        if severity in ["High", "Critical"] and confidence in ["High", "Medium"]:
            return True

        # Always generate PoC for certain vulnerability types
        vuln_types_always_poc = [
            "reentrancy",
            "flash-loan",
            "price-oracle",
            "access-control",
        ]

        finding_type = finding.get("type", "").lower()
        if any(vt in finding_type for vt in vuln_types_always_poc):
            return True

        return False

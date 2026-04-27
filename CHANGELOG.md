# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-alpha.2] - 2024-04-19

### Added
- **LangGraph orchestration** (`llm/graph.py`): Replaced sequential 6-pass pipeline with directed graph supporting parallel scanning agents, model tiering per node, and checkpointing. Architecture: recon → 4 parallel scan groups → dedup → adversarial → synthesis → poc → output.
- **Multi-model clients + ModelRouter** (`llm/clients/`, `llm/router.py`): Claude (Sonnet/Opus), GPT-4o, and Kimi K2.5 clients with unified `LLMClient` protocol. `ModelRouter.for_pass()` routes recon→Kimi, scan→Claude Sonnet, adversarial→Claude Opus, synthesis→GPT-4o, poc→Claude Sonnet. Falls back to Kimi if provider unavailable.
- **Cost/telemetry tracking** (`llm/telemetry.py`): `CostTracker` logs per-call tokens and USD cost. Per-model pricing tables included. Cost reports written to `./vulnhunter-results/cost_report.json`.
- **Halmos adapter** (`adapters/halmos_adapter.py`): Formal verification via symbolic execution. Parses counterexamples and assertion failures from `halmos` output into Critical/High findings.
- **ItyFuzz adapter** (`adapters/ityfuzz_adapter.py`): Hybrid fuzzer (symbolic + greybox) with flashloan detection for DeFi protocols.
- **RAG knowledge base** (`rag/store.py`, `rag/query.py`): ChromaDB vector store with `VulnStore` and `RAGQueryEngine`. Supports similarity search with metadata filtering.
- **Tree-sitter code segmentation** (`parsing/`): Solidity segmentation into contract/function/m modifier levels. Used by paranoid scanner and RAG chunking.
- **Scanner-to-LLM context pipeline** (`llm/scanner_context.py`): `format_scanner_findings_for_llm()` groups findings by multi-scanner agreement (≥2 scanners = high confidence).
- **Paranoid hypothesis pattern** (`llm/paranoid.py`): Forced-assumption scanning. Two-pass: Kimi filters plausible (segment, vuln_class) pairs; Claude Sonnet deep-analyzes. Configurable via `--paranoid` flag.
- **Tenderly fork PoC validation** (`integrations/tenderly.py`): `TenderlyClient` creates mainnet forks for PoC validation. Context manager ensures cleanup.
- **Multi-model consensus voting** (`llm/consensus.py`): `ConsensusScanner` runs same prompt on 2–3 models, votes on findings by fingerprint overlap.
- **`vulnhunter kb` command group** (`commands/kb.py`): `search`, `ingest`, `stats`, `reset` subcommands for knowledge base management.
- **Property test generator** (`poc/property_generator.py`): Auto-generates `check_*` Halmos property tests from recon invariant candidates.

### Changed
- `pyproject.toml` dependencies expanded: `langgraph`, `langgraph-checkpoint-sqlite`, `chromadb`, `tree-sitter`, `tree-sitter-solidity`, `tree-sitter-rust`.
- `config/settings.py` extended with `ClaudeConfig`, `OpenAIConfig`, `RoutingConfig`.
- `main.py` version bumped to `0.2.0-alpha.2`, `kb` command registered.

## [0.2.0-alpha.1] - 2024-04-19

### Added
- **Adversarial verification pass** (`llm/adversarial.py`): A dedicated devil's-advocate pass that receives all findings from the 6-pass pipeline and refutes false positives. Drops refuted findings, demotes uncertain findings by one severity level. Uses Claude Sonnet 4.6 via the `anthropic` SDK.
- **Attack vector knowledge base** (`knowledge/attack_vectors.py`): 64 curated attack vectors partitioned into 4 groups (Access Control, Reentrancy/External Calls, Math/Oracles, DeFi/Cross-Contract). Loader returns `dict[int, list[AttackVector]]`.
- **SMTChecker adapter** (`adapters/smtchecker_adapter.py`): Integrates `solc --model-checker-engine all` for mathematical proof of assertion correctness, overflow, division by zero, and unreachable code. Registered in scan command.
- **Pre-audit recon as Pass 0** (`llm/pipeline.py`): `AnalysisPipeline.analyze_findings` now accepts an optional `ReconReport` and injects a structured protocol context block into every pass prompt. Auto-runs recon if not supplied.
- **Impact × Likelihood severity matrix** (`models/severity_matrix.py`): New `derive_severity(impact, likelihood)` function. `Finding` model extended with `impact` and `likelihood` fields (1–5). All reporters updated to consume matrix fields.
- **MAKE_NO_MISTAKES directive** (`llm/prompts.py`): Every LLM pass prompt now ends with a verification directive requiring double-checking of claims against code, explicit uncertainty statements, and accuracy over speed.
- **CTFBench baseline harness** (`benchmarks/ctfbench_runner.py`): Automated benchmark runner that clones auditdbio/CTFBench, runs `vulnhunter hunt` on each contract, and computes VDR/OI scores. Baseline results committed to `benchmarks/results/`.

### Changed
- Bumped version to `0.2.0-alpha.1`.
- Updated all reporters (Codehawks, Immunefi, Code4rena, Sherlock) to prefer `finding.impact` / `finding.likelihood` over ad-hoc getattr patterns.

## [0.1.0] - 2024-03-24

### Added
- Initial release of SmartContract VulnHunter
- 15+ security scanner adapters (Slither, Aderyn, Mythril, Echidna, Medusa, Foundry, Heimdall, Trident, sec3 X-ray, cargo-audit, Caracal, Vyper, Solhint, Semgrep, 4naly3er)
- Multi-chain support (Ethereum, Solana, Cairo/Starknet, Vyper)
- 12 CLI commands (scan, report, bounty, clone, recon, analyze, poc, hunt, audit, status, config, monitor)
- LLM-powered 6-pass analysis pipeline (Kimi K2.5 integration)
- PoC auto-generation with Foundry test templates
- Platform-specific reporting (Immunefi, Code4rena, Sherlock, Codehawks)
- Knowledge base integration with 62,000+ vulnerability findings
- SARIF output normalization and deduplication
- Async orchestrator with semaphore-based concurrency
- Comprehensive test suite
- CI/CD pipeline with GitHub Actions
- Pre-commit hooks for code quality

### Security
- No private key storage
- Read-only blockchain access
- Safe subprocess execution (asyncio, no shell injection)
- API key management via environment variables

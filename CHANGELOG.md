# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

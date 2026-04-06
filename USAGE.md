# SmartContract VulnHunter

**Ultimate smart contract security CLI framework for bug bounty researchers**

## Installation

```bash
pip install -e .
```

## Usage

### Initialize configuration
```bash
vulnhunter config init
```

### Clone a repository
```bash
vulnhunter clone repo https://github.com/example/contracts.git
```

### Run security scan
```bash
vulnhunter scan run ./contracts --tools slither,aderyn --parallel 5
```

### Generate platform report
```bash
vulnhunter report generate ./vulnhunter-results --platform immunefi --output report.md
```

### Prepare bounty submission
```bash
vulnhunter bounty prepare findings.json --platform code4rena --output submission.md
```

## Supported Languages

- **Solidity** (10 adapters): Slither, Aderyn, Solhint, Semgrep, 4naly3er, Mythril, Echidna, Medusa, Foundry, Heimdall
- **Rust/Solana** (3 adapters): Trident, sec3 X-ray, cargo-audit
- **Vyper** (1 adapter): Slither-backed
- **Cairo** (1 adapter): Caracal

## Requirements

- Python 3.11+
- External tools (optional): Slither, Mythril, Foundry, etc.

## Testing

```bash
python tests/test_end_to_end.py
```

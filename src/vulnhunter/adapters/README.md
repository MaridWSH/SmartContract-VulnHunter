# Security Tool Adapters

This module provides async adapters for integrating external security analysis tools with the VulnHunter vulnerability detection system.

## Adapters

### HeimdallAdapter

EVM bytecode decompiler adapter.

**Tool**: `heimdall`
**Command**: `heimdall decompile <target>`
**Features**:
- Decompiles both raw bytecode and deployed contract addresses
- Parses JSON output with ABI and control flow information
- Extracts vulnerability information from structured output
- Handles non-zero exit codes gracefully

**Usage**:
```python
from vulnhunter.adapters import HeimdallAdapter

adapter = HeimdallAdapter()
if adapter.is_available():
    findings = await adapter.run("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")
    for finding in findings:
        print(f"{finding.title}: {finding.severity}")
```

**Output Parsing**:
- Attempts to parse JSON output
- Extracts items from keys: `vulnerabilities`, `issues`, `contracts`, `functions`, `abi`
- Falls back to generic findings if no structured data found

---

### TridentAdapter

Solana fuzzer adapter for Anchor programs.

**Tool**: `trident`
**Command**: `trident fuzz run <target>`
**Features**:
- Fuzzes Solana/Anchor programs
- Detects crashes, panics, and exceptions
- Parses both JSON and plain text output
- Supports timeout handling

**Usage**:
```python
from vulnhunter.adapters import TridentAdapter

adapter = TridentAdapter()
if adapter.is_available():
    findings = await adapter.run("target_program")
    crashes = [f for f in findings if "crash" in f.title.lower()]
    print(f"Found {len(crashes)} crashes")
```

**Crash Detection**:
- JSON mode: Parses crash objects with location information
- Text mode: Scans for patterns: `crash`, `panic`, `segfault`, `exception`
- Returns High severity findings for detected crashes

---

### CargoAuditAdapter

Rust dependency vulnerability scanner.

**Tool**: `cargo-audit`
**Command**: `cargo audit --json`
**Features**:
- Audits Cargo.toml dependencies for known vulnerabilities
- Parses multiple JSON output formats (v0.12+, older versions)
- Maps advisories to Finding model with severity
- Supports CVSS scoring

**Usage**:
```python
from vulnhunter.adapters import CargoAuditAdapter

adapter = CargoAuditAdapter()
if adapter.is_available():
    findings = await adapter.run("/path/to/rust/project")
    for finding in findings:
        print(f"{finding.title} in {finding.location}")
```

**Output Formats**:
- v0.12+: `{"vulnerabilities": {"list": [...]}}`
- Older: `{"advisories": {"RUSTSEC-...": {...}}}`
- Falls back to generic findings if parsing fails

---

## Common Interface

All adapters inherit from `ToolAdapter` and implement:

### `is_available() -> bool`
Check if the tool is installed and available in PATH.

### `async run(target: str) -> List[Finding]`
Execute the tool on the target and return findings.

**Parameters**:
- `target`: Path to file, directory, or identifier (depends on tool)

**Returns**:
- `List[Finding]`: Vulnerability findings with title, description, severity, location

---

## Testing

Run the test suite:

```bash
pytest tests/test_heimdall_adapter.py -v
pytest tests/test_trident_adapter.py -v
pytest tests/test_cargo_audit_adapter.py -v
```

Tests include:
- Unit tests with mocked subprocess outputs
- JSON parsing tests
- Error handling tests
- Integration tests (skipped if tool not installed)

---

## Installation Requirements

Install the underlying tools:

```bash
# Heimdall (EVM decompiler)
cargo install heimdall

# Trident (Solana fuzzer)
cargo install trident

# Cargo Audit (Rust deps)
cargo install cargo-audit
```

---

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│   Heimdall      │     │   Trident    │     │ CargoAudit  │
│   Adapter       │     │   Adapter    │     │  Adapter    │
└────────┬────────┘     └──────┬───────┘     └──────┬──────┘
         │                     │                    │
         └─────────────────────┼────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │   ToolAdapter       │
                    │   (Base Class)      │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │   Finding Model     │
                    └─────────────────────┘
```

All adapters use:
- **Asyncio subprocess**: Non-blocking execution
- **JSON parsing**: Structured output handling
- **Error handling**: Graceful failures with informative findings
- **Timeout support**: Prevents hanging on long-running tools

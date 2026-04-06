# Recon Playbook — Smart Contract Security Reconnaissance

A systematic, ecosystem-aware reconnaissance methodology for smart contract
security research. This playbook covers the full recon pipeline from repo
cloning to attack surface mapping across Solidity, Rust/Solana, Vyper, and Cairo.

## Table of Contents
1. [Phase 1: Target Acquisition](#phase-1-target-acquisition)
2. [Phase 2: Environment Setup & Build Verification](#phase-2-environment-setup--build-verification)
3. [Phase 3: Codebase Mapping](#phase-3-codebase-mapping)
4. [Phase 4: Architecture & Protocol Understanding](#phase-4-architecture--protocol-understanding)
5. [Phase 5: Attack Surface Enumeration](#phase-5-attack-surface-enumeration)
6. [Phase 6: Test Coverage & Gap Analysis](#phase-6-test-coverage--gap-analysis)
7. [Phase 7: Dependency & Supply Chain Audit](#phase-7-dependency--supply-chain-audit)
8. [Phase 8: Git History & Change Intelligence](#phase-8-git-history--change-intelligence)
9. [Phase 9: Prior Audit & Known Issue Check](#phase-9-prior-audit--known-issue-check)
10. [Phase 10: Recon Report Generation](#phase-10-recon-report-generation)
11. [Ecosystem-Specific Commands Reference](#ecosystem-specific-commands-reference)

---

## Phase 1: Target Acquisition

### 1.1 Clone & Pin the Codebase

```bash
# Clone with full history (needed for git analysis)
git clone --recurse-submodules <repo_url> /tmp/audit-target
cd /tmp/audit-target

# CRITICAL: Record the exact commit hash — this is your audit baseline
AUDIT_COMMIT=$(git rev-parse HEAD)
echo "Audit baseline commit: $AUDIT_COMMIT"
git log --oneline -1

# Tag it locally so you never lose it
git tag audit-baseline-$(date +%Y%m%d)
```

### 1.2 Collect Program Metadata

Before touching code, gather context from the user or program page:

- **Protocol name** and one-line description
- **Bug bounty program URL** (Immunefi, Code4rena, Sherlock, Codehawks)
- **Scope definition**: Which files/contracts are in scope? Which are out?
- **Program rules**: Severity definitions, exclusions, specific concerns
- **Previous audit reports**: Links or paths
- **Documentation**: Whitepaper, technical docs, architecture diagrams
- **Deployment info**: Chain(s), mainnet addresses, proxy patterns
- **TVL/Value at risk**: Current TVL from DefiLlama or protocol dashboard

Store all metadata in a structured `recon.toml` or `recon.json` at project root.

### 1.3 Detect the Ecosystem

```bash
# Auto-detect project type
detect_ecosystem() {
    if [ -f "foundry.toml" ] || [ -f "hardhat.config.js" ] || [ -f "hardhat.config.ts" ]; then
        echo "SOLIDITY_EVM"
    fi
    if [ -f "Anchor.toml" ] || ([ -f "Cargo.toml" ] && grep -q "solana" Cargo.toml 2>/dev/null); then
        echo "RUST_SOLANA"
    fi
    if find . -name "*.vy" -maxdepth 3 | grep -q .; then
        echo "VYPER"
    fi
    if [ -f "Scarb.toml" ] || [ -f "scarb.toml" ]; then
        echo "CAIRO_STARKNET"
    fi
    if [ -f "Cargo.toml" ] && grep -q "cosmwasm" Cargo.toml 2>/dev/null; then
        echo "RUST_COSMWASM"
    fi
}
detect_ecosystem
```

---

## Phase 2: Environment Setup & Build Verification

**You CANNOT write PoCs or run scanners on code that doesn't compile.**
This phase is non-negotiable.

### 2.1 Solidity/EVM

```bash
# Foundry (preferred)
if [ -f "foundry.toml" ]; then
    forge install
    forge build 2>&1 | tee /tmp/build-log-solidity.txt
    BUILD_STATUS=$?
    # Check compiler version
    grep -r "pragma solidity" --include="*.sol" src/ | sort -u
fi

# Hardhat
if [ -f "hardhat.config.js" ] || [ -f "hardhat.config.ts" ]; then
    npm install
    npx hardhat compile 2>&1 | tee /tmp/build-log-solidity.txt
fi

# Brownie (legacy)
if [ -f "brownie-config.yaml" ]; then
    pip install eth-brownie
    brownie compile 2>&1 | tee /tmp/build-log-solidity.txt
fi
```

### 2.2 Rust / Solana / Anchor

```bash
# Anchor programs
if [ -f "Anchor.toml" ]; then
    anchor build 2>&1 | tee /tmp/build-log-solana.txt
    # Check Anchor version
    anchor --version
    grep "anchor-lang" Cargo.toml
fi

# Native Solana programs
if [ -f "Cargo.toml" ] && grep -q "solana-program" Cargo.toml; then
    cargo build-sbf 2>&1 | tee /tmp/build-log-solana.txt
fi

# CosmWasm
if grep -q "cosmwasm" Cargo.toml 2>/dev/null; then
    cargo build --target wasm32-unknown-unknown --release 2>&1 | tee /tmp/build-log-cosmwasm.txt
fi
```

### 2.3 Vyper

```bash
# Vyper compilation
if command -v vyper &>/dev/null; then
    for f in $(find . -name "*.vy" -not -path "*/node_modules/*"); do
        echo "Compiling: $f"
        vyper "$f" 2>&1
    done | tee /tmp/build-log-vyper.txt
fi

# If using Ape framework
if [ -f "ape-config.yaml" ]; then
    ape compile 2>&1 | tee /tmp/build-log-vyper.txt
fi

# Check Vyper compiler version — CRITICAL for CVE-2023-30629
vyper --version 2>/dev/null
```

### 2.4 Cairo / Starknet

```bash
if [ -f "Scarb.toml" ] || [ -f "scarb.toml" ]; then
    scarb build 2>&1 | tee /tmp/build-log-cairo.txt
    # Check Cairo/Scarb version
    scarb --version
    grep "cairo-version" Scarb.toml 2>/dev/null || grep "cairo-version" scarb.toml 2>/dev/null
fi
```

### 2.5 Build Failure Triage

If build fails, diagnose and fix before proceeding:

- **Missing dependencies**: Check `.gitmodules`, `remappings.txt`, `package.json`
- **Wrong compiler version**: Pin to the version in pragma/config
- **Private/missing repos**: Check if submodules need auth tokens
- **Conflicting versions**: Check for solc version conflicts across files
- **Log everything**: Save build output — build errors sometimes reveal security issues

---

## Phase 3: Codebase Mapping

### 3.1 Project Structure Overview

```bash
# Directory tree (excluding noise)
find . -type f \( -name "*.sol" -o -name "*.rs" -o -name "*.vy" -o -name "*.cairo" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/target/*" \
    -not -path "*/lib/*" -not -path "*/deps/*" | sort

# File count by type
echo "=== File counts ==="
echo "Solidity: $(find . -name '*.sol' -not -path '*/lib/*' -not -path '*/node_modules/*' | wc -l)"
echo "Rust:     $(find . -name '*.rs' -not -path '*/target/*' | wc -l)"
echo "Vyper:    $(find . -name '*.vy' | wc -l)"
echo "Cairo:    $(find . -name '*.cairo' | wc -l)"

# Lines of code (scope estimate)
echo "=== Lines of code ==="
find . -name "*.sol" -not -path "*/lib/*" -not -path "*/node_modules/*" -exec cat {} + | wc -l
```

### 3.2 Identify In-Scope vs Out-of-Scope

```bash
# Common scope directories
echo "=== Likely in-scope ==="
ls -d src/ contracts/ programs/ 2>/dev/null

echo "=== Likely out-of-scope ==="
ls -d lib/ node_modules/ test/ tests/ script/ deploy/ 2>/dev/null

# If a scope.txt or scope file exists (common in contests)
find . -maxdepth 2 -name "*scope*" -o -name "*SCOPE*" 2>/dev/null
```

### 3.3 Complexity Metrics

```bash
# For Solidity — function counts and sizes per contract
grep -rn "function " --include="*.sol" src/ | wc -l
echo "Total functions in scope"

# Find large/complex files (likely high-value targets)
find . -name "*.sol" -not -path "*/lib/*" -exec wc -l {} + | sort -rn | head -20
echo "Largest source files (more code = more bugs)"

# Find contracts with many external calls (interaction surface)
grep -rn "\.call\|\.delegatecall\|\.staticcall\|\.transfer\|\.send" --include="*.sol" src/ | wc -l
echo "External call sites"
```

---

## Phase 4: Architecture & Protocol Understanding

### 4.1 Protocol Type Identification

Determine what kind of protocol this is — the vulnerability profile changes dramatically:

| Protocol Type | Key Risk Areas |
|--------------|---------------|
| Lending/Borrowing | Liquidation logic, oracle dependence, interest rate manipulation, bad debt |
| DEX/AMM | Price manipulation, sandwich attacks, LP inflation, fee extraction |
| Vault/Yield | First depositor attack, share price manipulation, harvest sandwiching |
| Bridge/Cross-chain | Message spoofing, replay attacks, finality assumptions |
| Governance/DAO | Flash loan voting, proposal griefing, timelock bypass |
| NFT/Marketplace | Royalty bypass, reentrancy via callbacks, metadata manipulation |
| Stablecoin | Depeg scenarios, collateral ratio manipulation, oracle failure |
| Oracle | TWAP manipulation, stale data, multi-oracle disagreement |
| Staking/Restaking | Withdrawal delays, slashing conditions, reward calculation errors |
| Token/Tokenomics | Supply manipulation, transfer hooks, fee-on-transfer edge cases |

### 4.2 Entry Point Mapping

Map every function that untrusted users can call:

```bash
# Solidity — all external/public functions
grep -rn "function.*\(external\|public\)" --include="*.sol" src/ | \
    grep -v "view\|pure\|internal\|private" | sort

# Solidity — all payable functions (value entry points)
grep -rn "payable" --include="*.sol" src/ | grep "function"

# Rust/Solana — all instruction handlers
grep -rn "pub fn\|#\[instruction\]" --include="*.rs" programs/ | sort

# Vyper — all external functions
grep -rn "@external" --include="*.vy" | sort

# Cairo — all external functions
grep -rn "#\[external\]\|fn " --include="*.cairo" src/ | sort
```

### 4.3 Access Control Map

```bash
# Solidity
echo "=== Access Control Modifiers ==="
grep -rn "onlyOwner\|onlyAdmin\|onlyRole\|onlyGovernance\|onlyKeeper\|onlyMinter\|whenNotPaused" \
    --include="*.sol" src/

echo "=== Require/Assert on msg.sender ==="
grep -rn "require.*msg.sender\|assert.*msg.sender" --include="*.sol" src/

echo "=== Role definitions ==="
grep -rn "bytes32.*ROLE\|keccak256.*ROLE" --include="*.sol" src/

# Rust/Solana
echo "=== Anchor constraints ==="
grep -rn "#\[account.*constraint\|has_one\|seeds\|signer\]" --include="*.rs" programs/
```

### 4.4 Token Flow & Value Mapping

```bash
# Where do tokens enter the protocol?
echo "=== Token inflows ==="
grep -rn "transferFrom\|safeTransferFrom\|deposit\|mint" --include="*.sol" src/

# Where do tokens leave the protocol?
echo "=== Token outflows ==="
grep -rn "transfer\|safeTransfer\|withdraw\|burn\|\.call{value" --include="*.sol" src/

# External protocol interactions
echo "=== External protocol calls ==="
grep -rn "interface\|import.*@" --include="*.sol" src/ | grep -v "openzeppelin\|solmate\|forge-std"
```

### 4.5 Upgrade & Admin Power Analysis

```bash
# Proxy patterns
echo "=== Proxy/Upgrade patterns ==="
grep -rn "Upgradeable\|UUPS\|TransparentProxy\|Beacon\|ERC1967\|delegatecall\|upgradeTo" \
    --include="*.sol" src/

# Admin power — functions that can change critical state
echo "=== Admin-only state changes ==="
grep -rn "onlyOwner\|onlyAdmin" --include="*.sol" src/ -A 5 | \
    grep "function\|=\|delete\|push\|pop"

# Emergency / pause mechanisms
echo "=== Emergency functions ==="
grep -rn "pause\|unpause\|emergency\|shutdown\|kill\|freeze" --include="*.sol" src/
```

---

## Phase 5: Attack Surface Enumeration

### 5.1 External Call Sites (Reentrancy Surface)

```bash
# All external calls (potential reentrancy)
echo "=== External calls ==="
grep -rn "\.call\|\.delegatecall\|\.staticcall" --include="*.sol" src/

# Transfer/send patterns
grep -rn "\.transfer\(|\.send\(" --include="*.sol" src/

# safeTransfer (ERC20) — check if CEI pattern is followed
grep -rn "safeTransfer\|safeTransferFrom" --include="*.sol" src/

# ERC-721/1155 safe mint/transfer (callback reentrancy)
grep -rn "safeMint\|safeTransferFrom\|_checkOnERC721Received\|onERC1155Received" \
    --include="*.sol" src/

# Solana CPI calls
grep -rn "invoke\|invoke_signed\|CpiContext" --include="*.rs" programs/
```

### 5.2 Math & Financial Logic

```bash
# Unchecked blocks (overflow risk in >=0.8.0)
grep -rn "unchecked" --include="*.sol" src/

# Division operations (precision loss risk)
grep -rn "[^/]/[^/\*]" --include="*.sol" src/ | grep -v "comment\|//"

# Casting operations (truncation risk)
grep -rn "uint8\|uint16\|uint32\|uint64\|uint96\|uint128\|int8\|int16\|int32" \
    --include="*.sol" src/ | grep -v "pragma"

# Assembly blocks (bypass safety checks)
grep -rn "assembly" --include="*.sol" src/
```

### 5.3 Oracle & Price Feed Usage

```bash
# Chainlink usage
grep -rn "AggregatorV3\|latestRoundData\|priceFeed\|oracle" --include="*.sol" src/

# TWAP / spot price usage
grep -rn "getReserves\|slot0\|observe\|consult\|TWAP" --include="*.sol" src/

# Custom oracle patterns
grep -rn "getPrice\|price()\|getRate\|exchangeRate" --include="*.sol" src/
```

### 5.4 Signature & Hash Operations

```bash
# ecrecover usage
grep -rn "ecrecover\|ECDSA\|recover\|SignatureChecker" --include="*.sol" src/

# Hash operations (collision risk)
grep -rn "abi.encodePacked.*keccak256\|keccak256.*abi.encodePacked" --include="*.sol" src/

# EIP-712 patterns
grep -rn "EIP712\|DOMAIN_SEPARATOR\|domainSeparator\|_hashTypedData" --include="*.sol" src/
```

### 5.5 Developer Breadcrumbs

```bash
# TODOs, FIXMEs, HACKs — developer-flagged issues
grep -rn "TODO\|FIXME\|HACK\|XXX\|BUG\|UNSAFE\|VULNERABILITY\|TEMP\|WORKAROUND" \
    --include="*.sol" --include="*.rs" --include="*.vy" --include="*.cairo" .

# Commented-out code (often reveals removed safeguards)
grep -rn "^[[:space:]]*//" --include="*.sol" src/ | grep -i "require\|assert\|check\|revert"
```

---

## Phase 6: Test Coverage & Gap Analysis

### 6.1 Existing Test Assessment

```bash
# Solidity / Foundry
echo "=== Test files ==="
find . -name "*.t.sol" -o -name "*.test.js" -o -name "*.test.ts" -o -name "*.spec.js" | sort

echo "=== Test count ==="
grep -rn "function test" --include="*.t.sol" test/ | wc -l

# Foundry coverage
forge coverage 2>/dev/null | tee /tmp/coverage-report.txt

# Hardhat coverage
npx hardhat coverage 2>/dev/null

# Anchor tests
anchor test 2>/dev/null | tee /tmp/test-output-solana.txt
```

### 6.2 Coverage Gap Identification

```bash
# Find source functions NOT mentioned in any test file
comm -23 \
    <(grep -rh "function " --include="*.sol" src/ | sed 's/.*function //' | sed 's/(.*//' | sort -u) \
    <(grep -rh "test\|assert\|expect" --include="*.t.sol" --include="*.test.*" test/ | \
        grep -oP '\w+' | sort -u) | head -30
echo "Functions potentially untested (approximate)"
```

### 6.3 Test Quality Assessment

Look for these red flags:
- **No fuzz tests**: Only unit tests = only happy paths tested
- **No invariant tests**: Protocol invariants not formally checked
- **Mocked dependencies**: Tests that mock external contracts miss integration issues
- **No fork tests**: Not tested against real mainnet state
- **No edge case tests**: No zero-value, max-value, or boundary tests

---

## Phase 7: Dependency & Supply Chain Audit

### 7.1 Solidity Dependencies

```bash
# Foundry dependencies (git submodules)
echo "=== Foundry libs ==="
cat .gitmodules 2>/dev/null
ls lib/ 2>/dev/null

# Check OpenZeppelin version (CVEs exist in older versions)
grep -r "openzeppelin" foundry.toml remappings.txt lib/ 2>/dev/null
cat lib/openzeppelin-contracts/.git/HEAD 2>/dev/null

# NPM dependencies (Hardhat)
cat package.json 2>/dev/null | grep -A 50 '"dependencies"'

# Check for known vulnerable dependency versions
# OpenZeppelin < 4.9.3 has multiple known issues
# Solmate has no formal audit
```

### 7.2 Rust/Solana Dependencies

```bash
# Cargo dependencies
cargo tree 2>/dev/null | head -50

# Known vulnerabilities
cargo audit 2>/dev/null | tee /tmp/cargo-audit.txt

# Check Anchor version (older versions have known bugs)
grep "anchor-lang" Cargo.toml
```

### 7.3 Cairo Dependencies

```bash
# Scarb dependencies
cat Scarb.toml 2>/dev/null | grep -A 20 "\[dependencies\]"
```

### 7.4 Custom vs Library Code

```bash
# Identify custom implementations of standard patterns (higher risk than library)
echo "=== Custom implementations (should be libraries?) ==="
grep -rn "function _transfer\|function _mint\|function _burn" --include="*.sol" src/ | \
    grep -v "override"
```

---

## Phase 8: Git History & Change Intelligence

### 8.1 Recent Activity Analysis

```bash
# Last 30 days of commits
echo "=== Recent commits (30 days) ==="
git log --oneline --since="30 days ago" --no-merges

# Files changed recently (high bug probability)
echo "=== Recently changed source files ==="
git log --since="30 days ago" --name-only --pretty=format: -- "*.sol" "*.rs" "*.vy" "*.cairo" | \
    sort | uniq -c | sort -rn | head -20

# Security-related commits (dedup signal)
echo "=== Security-related commits ==="
git log --oneline --all --grep="fix\|bug\|vuln\|security\|patch\|audit\|exploit\|reentrancy\|overflow" -i
```

### 8.2 Contributor Analysis

```bash
# Who wrote the code? (single author = higher risk, no peer review)
echo "=== Contributors ==="
git shortlog -sne --no-merges -- "*.sol" "*.rs" "*.vy" "*.cairo" | head -10

# Check for force pushes or history rewrites (suspicious)
git reflog --all | grep "forced" | head -5
```

### 8.3 Branch & PR Intelligence

```bash
# Check for fix/security branches
echo "=== Remote branches ==="
git branch -r | grep -i "fix\|patch\|security\|audit\|hotfix"

# Check if there are unmerged changes ahead of current branch
git log HEAD..origin/main --oneline 2>/dev/null
```

### 8.4 Diff Against Known-Good State

```bash
# If a previous audit commit is known, diff against it
# git diff <previous-audit-commit> HEAD -- src/
# This reveals ALL changes since last audit — focus your analysis here
```

---

## Phase 9: Prior Audit & Known Issue Check

### 9.1 Find Existing Audits

```bash
# Check repo for audit reports
find . -iname "*audit*" -o -iname "*security*" | grep -v node_modules | grep -v .git

# Check README for audit references
grep -i "audit\|security\|report\|trail of bits\|openzeppelin\|consensys\|certik\|cyfrin\|sherlock\|code4rena" \
    README.md 2>/dev/null

# Check for SECURITY.md
cat SECURITY.md 2>/dev/null
```

### 9.2 Known Issues & Bug Bounty History

```bash
# Check GitHub Issues for security-related reports
echo "Check manually:"
echo "  - GitHub Issues tagged 'bug' or 'security'"
echo "  - Immunefi program page for known issues"
echo "  - Solodit.xyz for related protocol findings"
echo "  - Code4rena/Sherlock past contest results if applicable"
```

### 9.3 On-Chain Deployment Verification

```bash
# If mainnet addresses are known, cross-reference:
echo "Verify:"
echo "  - Deployed bytecode matches source (Etherscan verified?)"
echo "  - Proxy implementation matches current source"
echo "  - Any pending governance proposals or upgrades"
echo "  - Current TVL from DefiLlama: https://defillama.com/"
```

---

## Phase 10: Recon Report Generation

The recon phase produces a structured report consumed by the LLM analysis pipeline:

```markdown
# Recon Report: [Protocol Name]

## Target
- Repository: <url>
- Commit: <hash>
- Date: <date>
- Ecosystem: Solidity / Rust-Solana / Vyper / Cairo

## Build Status
- Compiler: solc 0.8.x / anchor 0.x / vyper 0.x / scarb 0.x
- Build: PASS / FAIL (with error log)
- Test suite: X tests, Y passing, Z failing

## Scope
- In-scope files: [list]
- Out-of-scope files: [list]
- Lines of code: X
- Total functions: Y (X external, Y public, Z internal)

## Protocol Profile
- Type: Lending / DEX / Vault / Bridge / ...
- TVL: $X
- Chains: Ethereum / Solana / Starknet / ...
- Upgrade pattern: UUPS / Transparent / Immutable

## Architecture Summary
- Key contracts and their roles
- Trust hierarchy: Owner → Admin → Keeper → User
- External dependencies: Chainlink / Uniswap / ...
- Token flows: [deposit → pool → withdraw]

## Attack Surface
- External call sites: X
- Payable functions: X
- Oracle dependencies: X
- Assembly blocks: X
- Unchecked blocks: X
- Signature operations: X
- Cross-contract interactions: X

## Risk Indicators
- Test coverage: X%
- Untested functions: [list]
- Recently changed files: [list with commit counts]
- Developer TODOs/FIXMEs: X
- Single-author files: [list]
- Custom implementations (not library): [list]

## Dependency Health
- OpenZeppelin version: X (known CVEs: Y/N)
- Other deps: [list with versions]
- cargo audit / npm audit results: [summary]

## Prior Security
- Previous audits: [list with links]
- Known issues: [list]
- Security-related commits: [list]
- Bug bounty program: [link]

## Hot Zones (Priority Targets)
1. [file:function] — Reason: complex logic, recently changed, untested
2. [file:function] — Reason: handles value, external calls, no reentrancy guard
3. ...
```

---

## Ecosystem-Specific Commands Reference

### Solidity/EVM Quick Reference

```bash
# Full recon pipeline
forge build                                    # Compile
forge coverage                                 # Test coverage
slither . --json slither-report.json           # Static analysis
aderyn . -o aderyn-report.json                 # Fast static analysis
solhint 'src/**/*.sol' -f json                 # Linting
forge inspect <Contract> storage-layout        # Storage layout (proxy audit)
forge inspect <Contract> abi                   # ABI (entry points)
cast interface <address> --rpc-url $RPC        # ABI from deployed contract
cast code <address> --rpc-url $RPC             # Check if contract exists
```

### Rust/Solana Quick Reference

```bash
# Full recon pipeline
anchor build                                   # Compile
anchor test                                    # Run tests
cargo audit                                    # Dependency vulnerabilities
cargo clippy -- -W clippy::all                 # Linting
# sec3 X-ray (if available)
# trident fuzz (if invariants defined)

# Key patterns to search
grep -rn "invoke_signed\|invoke\|CpiContext" --include="*.rs" programs/
grep -rn "#\[account\]" --include="*.rs" programs/
grep -rn "unchecked\|wrapping" --include="*.rs" programs/
```

### Vyper Quick Reference

```bash
# Full recon pipeline
vyper <file.vy>                                # Compile single file
slither . --json slither-report.json           # Slither supports Vyper
# Titanoboa for testing

# CRITICAL: Check compiler version for CVE-2023-30629
vyper --version
# Affected: 0.2.15, 0.2.16, 0.3.0
# @nonreentrant decorator broken in these versions

# Key patterns to search
grep -rn "@nonreentrant" --include="*.vy"      # Reentrancy guards
grep -rn "@external" --include="*.vy"          # Entry points
grep -rn "raw_call\|send\|create" --include="*.vy"  # External interactions
```

### Cairo/Starknet Quick Reference

```bash
# Full recon pipeline
scarb build                                    # Compile
scarb test                                     # Run tests
# caracal detect <path>                        # Static analysis (if available)

# Key patterns to search
grep -rn "#\[external\]" --include="*.cairo"   # Entry points
grep -rn "felt252" --include="*.cairo"         # Field arithmetic (overflow risk)
grep -rn "replace_class_syscall" --include="*.cairo"  # Upgrade mechanism
grep -rn "call_contract_syscall\|library_call" --include="*.cairo"  # External calls
grep -rn "get_caller_address" --include="*.cairo"  # Access control
```
